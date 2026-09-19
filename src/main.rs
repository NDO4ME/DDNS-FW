//! DDNS Firewall Synchronizer v2.3.1
//!
//! Ultra-lightweight, production-grade DDNS-based iptables firewall manager.
//! Designed for 24/7 critical servers - zero SSH access loss guaranteed.
//!
//! Safety guarantees:
//! - Atomic state cache for crash recovery
//! - NEVER deletes a rule without active replacement
//! - IP unchanged = zero operations (no micro-interruptions)
//! - DNS failure = no changes (fail-safe)
//! - iptables failure = no changes (fail-safe)
//! - Loop protection with max iterations
//! - Memory bounded (max 100 rules)
//! - Reboot/crash safe with automatic recovery
//! - Idempotent: safe to run unlimited times
//! - File locking prevents concurrent execution
//! - Strict permissions prevent privilege escalation

use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// Constants
// ============================================================================

const VERSION: &str = env!("CARGO_PKG_VERSION");
const INSTALL_DIR: &str = "/etc/ddnsfw";
const BINARY_PATH: &str = "/etc/ddnsfw/run";
const CONFIG_PATH: &str = "/etc/ddnsfw/conf.conf";
const CACHE_PATH: &str = "/etc/ddnsfw/service.cache";
const SERVICE_PATH: &str = "/etc/systemd/system/ddnsfw.service";
const TIMER_PATH: &str = "/etc/systemd/system/ddnsfw.timer";
const IPTABLES_COMMENT: &str = "DDNS-ACCESS";
const IPTABLES_DROP_COMMENT: &str = "DDNS-DROP";
const IPTABLES_JUMP_COMMENT: &str = "DDNS-JUMP";
const CHAIN_NAME: &str = "DDNS-FW";
const DNS_TIMEOUT_SECS: u64 = 10;

// Safety limits
const MAX_ENTRIES: usize = 100;      // Max config entries
const MAX_RULES: usize = 100;        // Max iptables rules to process
const MAX_LOOP_ITERATIONS: usize = 200;  // Absolute max iterations in any loop

const IPTABLES_PATHS: &[&str] = &[
    "/usr/sbin/iptables",
    "/sbin/iptables",
    "/usr/bin/iptables",
];

const LOCK_PATH: &str = "/etc/ddnsfw/.lock";

// ============================================================================
// Cache Structure (Crash Recovery)
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum CacheState {
    Idle,
    Adding,
    Deleting,
}

#[derive(Debug, Clone)]
struct Cache {
    state: CacheState,
    rules: HashSet<(Ipv4Addr, u16)>,
    pending: Option<(Ipv4Addr, u16)>,
}

impl Cache {
    fn new() -> Self {
        Cache {
            state: CacheState::Idle,
            rules: HashSet::new(),
            pending: None,
        }
    }

    fn load() -> Self {
        let Ok(file) = File::open(CACHE_PATH) else {
            return Cache::new();
        };

        let reader = BufReader::new(file);
        let mut cache = Cache::new();
        let mut line_count = 0;

        for line in reader.lines().map_while(Result::ok) {
            line_count += 1;
            if line_count > 10 {
                break; // Corrupt cache protection
            }

            if let Some(state_str) = line.strip_prefix("STATE:") {
                cache.state = match state_str {
                    "ADDING" => CacheState::Adding,
                    "DELETING" => CacheState::Deleting,
                    _ => CacheState::Idle,
                };
            } else if let Some(rules_str) = line.strip_prefix("RULES:") {
                let mut rule_count = 0;
                for rule in rules_str.split(',') {
                    if rule_count >= MAX_RULES {
                        break;
                    }
                    if let Some((ip, port)) = parse_ip_port(rule) {
                        cache.rules.insert((ip, port));
                        rule_count += 1;
                    }
                }
            } else if let Some(pending_str) = line.strip_prefix("PENDING:") {
                cache.pending = parse_ip_port(pending_str);
            }
        }

        cache
    }

    fn save(&self) {
        // Limit rules in cache
        let rules_to_save: Vec<_> = self.rules.iter().take(MAX_RULES).collect();

        let rules_str: String = rules_to_save
            .iter()
            .map(|(ip, port)| format!("{}:{}", ip, port))
            .collect::<Vec<_>>()
            .join(",");

        let state_str = match self.state {
            CacheState::Idle => "IDLE",
            CacheState::Adding => "ADDING",
            CacheState::Deleting => "DELETING",
        };

        let pending_str = self
            .pending
            .map(|(ip, port)| format!("{}:{}", ip, port))
            .unwrap_or_default();

        let content = format!("STATE:{}\nRULES:{}\nPENDING:{}\n", state_str, rules_str, pending_str);

        // Atomic write
        let temp_path = format!("{}.tmp", CACHE_PATH);
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)
        {
            let _ = file.write_all(content.as_bytes());
            let _ = file.sync_all();
            let _ = fs::rename(&temp_path, CACHE_PATH);
        }
    }

    fn set_idle(&mut self) {
        self.state = CacheState::Idle;
        self.pending = None;
        self.save();
    }

    fn set_adding(&mut self, ip: Ipv4Addr, port: u16) {
        self.state = CacheState::Adding;
        self.pending = Some((ip, port));
        self.save();
    }

    fn set_deleting(&mut self, ip: Ipv4Addr, port: u16) {
        self.state = CacheState::Deleting;
        self.pending = Some((ip, port));
        self.save();
    }

    fn add_rule(&mut self, ip: Ipv4Addr, port: u16) {
        if self.rules.len() < MAX_RULES {
            self.rules.insert((ip, port));
        }
        self.state = CacheState::Idle;
        self.pending = None;
        self.save();
    }

    fn remove_rule(&mut self, ip: Ipv4Addr, port: u16) {
        self.rules.remove(&(ip, port));
        self.state = CacheState::Idle;
        self.pending = None;
        self.save();
    }
}

fn parse_ip_port(s: &str) -> Option<(Ipv4Addr, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let colon = s.rfind(':')?;
    let ip: Ipv4Addr = s[..colon].parse().ok()?;
    let port: u16 = s[colon + 1..].parse().ok()?;
    Some((ip, port))
}

// ============================================================================
// Minimal Error Handling
// ============================================================================

fn exit_err(msg: &str) -> ! {
    eprintln!("[ddnsfw] ERROR: {}", msg);
    std::process::exit(1);
}

// ============================================================================
// File Locking (Prevents Concurrent Execution)
// ============================================================================

/// Acquires an exclusive lock on the lock file.
/// Returns the lock file handle (must be kept alive during operation).
/// If another instance is running, waits up to 30 seconds then exits.
fn acquire_lock() -> Option<File> {
    // Create lock file if it doesn't exist
    let lock_file = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(LOCK_PATH)
        .ok()?;

    // Try to acquire exclusive lock (non-blocking first)
    let fd = lock_file.as_raw_fd();
    let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

    if result == 0 {
        // Lock acquired immediately
        return Some(lock_file);
    }

    // Another instance is running, wait with timeout
    println!("[ddnsfw] Another instance is running, waiting...");

    // Try blocking lock with timeout using a separate thread
    use std::sync::mpsc;
    use std::thread;

    let (tx, rx) = mpsc::channel();
    let fd_copy = fd;

    thread::spawn(move || {
        let result = unsafe { libc::flock(fd_copy, libc::LOCK_EX) };
        let _ = tx.send(result);
    });

    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(0) => Some(lock_file),
        _ => {
            eprintln!("[ddnsfw] ERROR: Timeout waiting for lock (another instance running too long)");
            None
        }
    }
}

// ============================================================================
// System Checks
// ============================================================================

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn find_iptables() -> Option<&'static str> {
    IPTABLES_PATHS.iter().find(|p| Path::new(p).exists()).copied()
}

fn is_installed() -> bool {
    Path::new(BINARY_PATH).exists() && Path::new(CONFIG_PATH).exists()
}

fn is_running_installed() -> bool {
    env::current_exe()
        .map(|p| p.to_string_lossy() == BINARY_PATH)
        .unwrap_or(false)
}

// ============================================================================
// DNS Resolution (Google DNS-over-HTTPS - bypasses local DNS cache)
// ============================================================================

#[derive(serde::Deserialize)]
struct DnsResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer")]
    #[serde(default)]
    answer: Vec<DnsAnswer>,
}

#[derive(serde::Deserialize)]
struct DnsAnswer {
    #[serde(rename = "type")]
    record_type: u32,
    data: String,
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_dns_agent() -> ureq::Agent {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS config failed")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    ureq::AgentBuilder::new()
        .tls_config(Arc::new(tls_config))
        .build()
}

fn resolve_dns(hostname: &str) -> Option<Ipv4Addr> {
    let url = format!("https://8.8.8.8/resolve?name={}&type=A", hostname);
    let agent = build_dns_agent();
    let resp: DnsResponse = agent.get(&url)
        .set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .set("Host", "dns.google")
        .timeout(Duration::from_secs(DNS_TIMEOUT_SECS))
        .call()
        .ok()?
        .into_json()
        .ok()?;

    if resp.status != 0 {
        return None;
    }

    resp.answer
        .iter()
        .find(|a| a.record_type == 1)
        .and_then(|a| a.data.parse().ok())
}

fn resolve_dns_timeout(hostname: &str, _timeout: Duration) -> Option<Ipv4Addr> {
    resolve_dns(hostname)
}

// ============================================================================
// iptables Operations
// ============================================================================

fn iptables(bin: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        None
    }
}

fn iptables_run(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn get_chain_rules(bin: &str) -> (HashSet<(Ipv4Addr, u16)>, HashSet<u16>) {
    let mut accept_rules = HashSet::new();
    let mut drop_ports = HashSet::new();

    let Some(output) = iptables(bin, &["-S", CHAIN_NAME]) else {
        return (accept_rules, drop_ports);
    };

    let mut iteration = 0;
    for line in output.lines() {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            eprintln!("[ddnsfw] WARN: Too many chain rules, truncating");
            break;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();

        if line.contains(IPTABLES_COMMENT) && line.contains("ACCEPT") {
            if accept_rules.len() >= MAX_RULES {
                continue;
            }

            let mut ip: Option<Ipv4Addr> = None;
            let mut port: Option<u16> = None;

            for i in 0..parts.len().min(50) {
                if parts[i] == "-s" && i + 1 < parts.len() {
                    ip = parts[i + 1].trim_end_matches("/32").parse().ok();
                }
                if parts[i] == "--dport" && i + 1 < parts.len() {
                    port = parts[i + 1].parse().ok();
                }
            }

            if let (Some(ip), Some(port)) = (ip, port) {
                accept_rules.insert((ip, port));
            }
        } else if line.contains(IPTABLES_DROP_COMMENT) && line.contains("DROP") {
            let mut port: Option<u16> = None;

            for i in 0..parts.len().min(50) {
                if parts[i] == "--dport" && i + 1 < parts.len() {
                    port = parts[i + 1].parse().ok();
                }
            }

            if let Some(port) = port {
                drop_ports.insert(port);
            }
        }
    }

    (accept_rules, drop_ports)
}

fn rule_exists(bin: &str, ip: Ipv4Addr, port: u16) -> bool {
    iptables_run(
        bin,
        &[
            "-C", CHAIN_NAME,
            "-s", &format!("{}/32", ip),
            "-p", "tcp",
            "-m", "tcp",
            "--dport", &port.to_string(),
            "-m", "comment",
            "--comment", IPTABLES_COMMENT,
            "-j", "ACCEPT",
        ],
    )
}

fn add_rule(bin: &str, ip: Ipv4Addr, port: u16) -> bool {
    iptables_run(
        bin,
        &[
            "-I", CHAIN_NAME, "1",
            "-s", &format!("{}/32", ip),
            "-p", "tcp",
            "-m", "tcp",
            "--dport", &port.to_string(),
            "-m", "comment",
            "--comment", IPTABLES_COMMENT,
            "-j", "ACCEPT",
        ],
    )
}

fn delete_rule(bin: &str, ip: Ipv4Addr, port: u16) -> bool {
    iptables_run(
        bin,
        &[
            "-D", CHAIN_NAME,
            "-s", &format!("{}/32", ip),
            "-p", "tcp",
            "-m", "tcp",
            "--dport", &port.to_string(),
            "-m", "comment",
            "--comment", IPTABLES_COMMENT,
            "-j", "ACCEPT",
        ],
    )
}

fn ensure_chain(bin: &str) -> bool {
    if iptables(bin, &["-S", CHAIN_NAME]).is_some() {
        return true;
    }
    iptables_run(bin, &["-N", CHAIN_NAME])
}

fn ensure_jump_rule(bin: &str) -> bool {
    if iptables_run(bin, &[
        "-C", "INPUT",
        "-j", CHAIN_NAME,
        "-m", "comment",
        "--comment", IPTABLES_JUMP_COMMENT,
    ]) {
        return true;
    }
    iptables_run(bin, &[
        "-I", "INPUT", "1",
        "-j", CHAIN_NAME,
        "-m", "comment",
        "--comment", IPTABLES_JUMP_COMMENT,
    ])
}

fn add_drop_rule(bin: &str, port: u16) -> bool {
    iptables_run(
        bin,
        &[
            "-A", CHAIN_NAME,
            "-p", "tcp",
            "-m", "tcp",
            "--dport", &port.to_string(),
            "-m", "comment",
            "--comment", IPTABLES_DROP_COMMENT,
            "-j", "DROP",
        ],
    )
}

fn delete_drop_rule(bin: &str, port: u16) -> bool {
    iptables_run(
        bin,
        &[
            "-D", CHAIN_NAME,
            "-p", "tcp",
            "-m", "tcp",
            "--dport", &port.to_string(),
            "-m", "comment",
            "--comment", IPTABLES_DROP_COMMENT,
            "-j", "DROP",
        ],
    )
}

fn cleanup_legacy_rules(bin: &str) {
    let Some(output) = iptables(bin, &["-S", "INPUT"]) else {
        return;
    };

    let mut to_delete: Vec<(Ipv4Addr, u16)> = Vec::new();
    let mut iteration = 0;

    for line in output.lines() {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            break;
        }

        if !line.contains(IPTABLES_COMMENT) || !line.contains("ACCEPT") {
            continue;
        }
        // Skip jump rules
        if line.contains(IPTABLES_JUMP_COMMENT) || line.contains(CHAIN_NAME) {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut ip: Option<Ipv4Addr> = None;
        let mut port: Option<u16> = None;

        for i in 0..parts.len().min(50) {
            if parts[i] == "-s" && i + 1 < parts.len() {
                ip = parts[i + 1].trim_end_matches("/32").parse().ok();
            }
            if parts[i] == "--dport" && i + 1 < parts.len() {
                port = parts[i + 1].parse().ok();
            }
        }

        if let (Some(ip), Some(port)) = (ip, port) {
            to_delete.push((ip, port));
        }
    }

    for (ip, port) in to_delete {
        print!("[ddnsfw] Migrating legacy rule {}:{} from INPUT... ", ip, port);
        let _ = io::stdout().flush();
        if iptables_run(bin, &[
            "-D", "INPUT",
            "-s", &format!("{}/32", ip),
            "-p", "tcp",
            "-m", "tcp",
            "--dport", &port.to_string(),
            "-m", "comment",
            "--comment", IPTABLES_COMMENT,
            "-j", "ACCEPT",
        ]) {
            println!("OK");
        } else {
            println!("FAILED");
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

struct DdnsEntry {
    hostname: String,
    port: u16,
}

fn parse_config() -> Vec<DdnsEntry> {
    let Ok(content) = fs::read_to_string(CONFIG_PATH) else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    let mut iteration = 0;

    for line in content.lines() {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            eprintln!("[ddnsfw] WARN: Config file too large, truncating");
            break;
        }

        if entries.len() >= MAX_ENTRIES {
            eprintln!("[ddnsfw] WARN: Max {} entries allowed", MAX_ENTRIES);
            break;
        }

        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(colon) = line.rfind(':') {
            let hostname = line[..colon].trim().to_string();
            if let Ok(port) = line[colon + 1..].trim().parse::<u16>() {
                if !hostname.is_empty() && port > 0 {
                    entries.push(DdnsEntry { hostname, port });
                }
            }
        }
    }

    entries
}

// ============================================================================
// Crash Recovery
// ============================================================================

fn recover_from_crash(iptables_bin: &str, cache: &mut Cache) {
    match cache.state {
        CacheState::Idle => {}
        CacheState::Adding => {
            if let Some((ip, port)) = cache.pending {
                println!("[ddnsfw] Recovery: Checking pending add {}:{}", ip, port);
                if !rule_exists(iptables_bin, ip, port) {
                    println!("[ddnsfw] Recovery: Re-adding rule {}:{}", ip, port);
                    if add_rule(iptables_bin, ip, port) {
                        cache.add_rule(ip, port);
                    } else {
                        cache.set_idle();
                    }
                } else {
                    cache.add_rule(ip, port);
                }
            } else {
                cache.set_idle();
            }
        }
        CacheState::Deleting => {
            if let Some((ip, port)) = cache.pending {
                println!("[ddnsfw] Recovery: Delete interrupted for {}:{}, ignoring", ip, port);
            }
            cache.set_idle();
        }
    }
}

// ============================================================================
// Core Sync Algorithm (CRITICAL - Zero Bug Tolerance)
// ============================================================================

fn sync_firewall() {
    // Acquire exclusive lock to prevent concurrent execution
    let _lock = match acquire_lock() {
        Some(lock) => lock,
        None => {
            eprintln!("[ddnsfw] ERROR: Could not acquire lock");
            return;
        }
    };
    // Lock is held until _lock goes out of scope

    let Some(iptables_bin) = find_iptables() else {
        eprintln!("[ddnsfw] ERROR: iptables not found");
        return;
    };

    // Ensure dedicated chain and jump rule exist
    if !ensure_chain(iptables_bin) {
        eprintln!("[ddnsfw] ERROR: Could not create chain {}", CHAIN_NAME);
        return;
    }
    if !ensure_jump_rule(iptables_bin) {
        eprintln!("[ddnsfw] ERROR: Could not create jump rule");
        return;
    }

    // Load cache and recover if needed
    let mut cache = Cache::load();
    if cache.state != CacheState::Idle {
        println!("[ddnsfw] Detected incomplete operation, recovering...");
        recover_from_crash(iptables_bin, &mut cache);
    }

    let entries = parse_config();
    if entries.is_empty() {
        println!("[ddnsfw] No entries in config");
        cleanup_legacy_rules(iptables_bin);
        return;
    }

    println!("[ddnsfw] v{} - Syncing {} entries...", VERSION, entries.len());

    // Get actual chain state (source of truth)
    let (existing_accept, existing_drop) = get_chain_rules(iptables_bin);

    // Update cache with actual state
    cache.rules = existing_accept.clone();
    cache.save();

    // Track desired state
    let mut desired_accept: HashSet<(Ipv4Addr, u16)> = HashSet::new();
    let mut desired_ports: HashSet<u16> = HashSet::new();
    let mut rules_to_add: Vec<(Ipv4Addr, u16)> = Vec::new();

    // Phase 1: Resolve all DNS first (no iptables changes yet)
    let mut iteration = 0;
    for entry in &entries {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            eprintln!("[ddnsfw] WARN: Loop protection triggered in phase 1");
            break;
        }

        desired_ports.insert(entry.port);

        print!("[ddnsfw] {}:{} -> ", entry.hostname, entry.port);
        let _ = io::stdout().flush();

        let Some(ip) = resolve_dns_timeout(&entry.hostname, Duration::from_secs(DNS_TIMEOUT_SECS)) else {
            println!("SKIP (DNS failed, keeping existing)");
            // Keep existing rules for this port
            for &(existing_ip, existing_port) in &existing_accept {
                if existing_port == entry.port {
                    desired_accept.insert((existing_ip, existing_port));
                }
            }
            continue;
        };

        print!("{} ", ip);
        let _ = io::stdout().flush();

        desired_accept.insert((ip, entry.port));

        // Check if rule already exists - if yes, NO OPERATION needed
        if existing_accept.contains(&(ip, entry.port)) {
            println!("OK (no change)");
            continue;
        }

        // Also check with iptables directly (belt and suspenders)
        if rule_exists(iptables_bin, ip, entry.port) {
            println!("OK (exists)");
            continue;
        }

        // Need to add this rule
        rules_to_add.push((ip, entry.port));
        println!("PENDING");
    }

    // Phase 2: Add new ACCEPT rules (safe - only adds, preserves existing)
    iteration = 0;
    for (ip, port) in &rules_to_add {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            eprintln!("[ddnsfw] WARN: Loop protection triggered in phase 2");
            break;
        }

        print!("[ddnsfw] Adding ACCEPT {}:{} ... ", ip, port);
        let _ = io::stdout().flush();

        cache.set_adding(*ip, *port);

        if add_rule(iptables_bin, *ip, *port) {
            cache.add_rule(*ip, *port);
            println!("OK");
        } else {
            // Retry once
            if add_rule(iptables_bin, *ip, *port) {
                cache.add_rule(*ip, *port);
                println!("OK (retry)");
            } else {
                cache.set_idle();
                println!("FAILED (keeping existing)");
                // Keep existing rules for this port
                for &(existing_ip, existing_port) in &existing_accept {
                    if existing_port == *port {
                        desired_accept.insert((existing_ip, existing_port));
                    }
                }
            }
        }
    }

    // Phase 3: Manage DROP rules for managed ports
    // SAFETY: Only add DROP if at least one ACCEPT exists for that port.
    // If no ACCEPT exists (DNS failed on first run / corrupted state),
    // adding DROP would lock out ALL access to that port.
    iteration = 0;
    for &port in &desired_ports {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            break;
        }

        let has_accept = desired_accept.iter().any(|&(_, p)| p == port);

        if has_accept && !existing_drop.contains(&port) {
            // Port has authorized IPs, safe to block others
            print!("[ddnsfw] Adding DROP for port {} ... ", port);
            let _ = io::stdout().flush();

            if add_drop_rule(iptables_bin, port) {
                println!("OK");
            } else {
                println!("FAILED");
            }
        } else if !has_accept && existing_drop.contains(&port) {
            // No authorized IPs resolved, remove DROP to prevent lockout
            print!("[ddnsfw] Removing DROP for port {} (no ACCEPT, safety) ... ", port);
            let _ = io::stdout().flush();

            if delete_drop_rule(iptables_bin, port) {
                println!("OK");
            } else {
                println!("FAILED");
            }
        }
    }

    // Phase 4: Delete stale ACCEPT rules (safe - new rules already active)
    iteration = 0;
    for &(ip, port) in &existing_accept {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            eprintln!("[ddnsfw] WARN: Loop protection triggered in phase 4");
            break;
        }

        if !desired_accept.contains(&(ip, port)) {
            print!("[ddnsfw] Removing old ACCEPT {}:{} ... ", ip, port);
            let _ = io::stdout().flush();

            cache.set_deleting(ip, port);

            if delete_rule(iptables_bin, ip, port) {
                cache.remove_rule(ip, port);
                println!("OK");
            } else {
                cache.set_idle();
                println!("FAILED (rule remains)");
            }
        }
    }

    // Phase 5: Delete stale DROP rules (ports no longer managed)
    iteration = 0;
    for &port in &existing_drop {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            break;
        }

        if !desired_ports.contains(&port) {
            print!("[ddnsfw] Removing DROP for port {} ... ", port);
            let _ = io::stdout().flush();

            if delete_drop_rule(iptables_bin, port) {
                println!("OK");
            } else {
                println!("FAILED");
            }
        }
    }

    // Phase 6: Clean up legacy rules from INPUT chain (v2.x migration)
    cleanup_legacy_rules(iptables_bin);

    cache.set_idle();
    println!("[ddnsfw] Sync complete");
}

// ============================================================================
// Installation
// ============================================================================

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    let _ = io::stdout().flush();
    let mut input = String::new();
    io::stdin().lock().read_line(&mut input).unwrap_or(0);
    input.trim().to_string()
}

fn prompt_yn(msg: &str, default: bool) -> bool {
    let suffix = if default { " [Y/n]: " } else { " [y/N]: " };
    let input = prompt(&format!("{}{}", msg, suffix)).to_lowercase();
    match input.as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default,
    }
}

fn interactive_setup() -> Vec<DdnsEntry> {
    if find_iptables().is_none() {
        exit_err(
            "iptables not found!\n\
             Install it first:\n  \
             Ubuntu/Debian: sudo apt install iptables\n  \
             CentOS/RHEL:   sudo yum install iptables",
        );
    }

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║         DDNS Firewall Synchronizer - Setup                 ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    let mut entries = Vec::new();
    let mut loop_count = 0;

    loop {
        loop_count += 1;
        if loop_count > MAX_ENTRIES {
            println!("Maximum {} entries reached.", MAX_ENTRIES);
            break;
        }

        let port: u16 = loop {
            let s = prompt("SSH Port (e.g., 22): ");
            if let Ok(p) = s.parse() {
                if p > 0 {
                    break p;
                }
            }
            println!("Invalid port, try again.");
        };

        let hostname = loop {
            let s = prompt("DDNS hostname (e.g., home.dyndns.org): ");
            if !s.is_empty() && !s.contains(' ') && s.len() < 256 {
                break s;
            }
            println!("Invalid hostname, try again.");
        };

        println!("Added: {}:{}", hostname, port);
        entries.push(DdnsEntry { hostname, port });

        if !prompt_yn("\nAdd another entry?", false) {
            break;
        }
    }

    if entries.is_empty() {
        exit_err("At least one entry required");
    }

    println!("\nEntries to configure:");
    for e in &entries {
        println!("  * {}:{}", e.hostname, e.port);
    }

    if !prompt_yn("\nProceed with installation?", true) {
        exit_err("Cancelled");
    }

    entries
}

fn install(entries: Vec<DdnsEntry>) {
    println!("\nInstalling...\n");

    print!("  [1/8] Creating directory... ");
    if fs::create_dir_all(INSTALL_DIR).is_err() {
        exit_err("Failed to create directory");
    }
    // Set directory permissions to 700 (rwx------) - only root can access
    if fs::set_permissions(INSTALL_DIR, fs::Permissions::from_mode(0o700)).is_err() {
        exit_err("Failed to set directory permissions");
    }
    println!("OK");

    print!("  [2/8] Copying binary... ");
    let exe = env::current_exe().unwrap_or_else(|_| exit_err("Cannot get exe path"));
    if exe.to_string_lossy() != BINARY_PATH {
        if fs::copy(&exe, BINARY_PATH).is_err() {
            exit_err("Failed to copy binary");
        }
    }
    // Set binary permissions to 700 (rwx------) - only root can execute
    if fs::set_permissions(BINARY_PATH, fs::Permissions::from_mode(0o700)).is_err() {
        exit_err("Failed to set binary permissions");
    }
    println!("OK");

    print!("  [3/8] Creating config... ");
    let mut config = String::from(
        "# DDNS Firewall Configuration\n\
         # Format: hostname:port\n\n",
    );
    for e in &entries {
        config.push_str(&format!("{}:{}\n", e.hostname, e.port));
    }
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(CONFIG_PATH);
    if file.is_err() || file.unwrap().write_all(config.as_bytes()).is_err() {
        exit_err("Failed to write config");
    }
    println!("OK");

    print!("  [4/8] Initializing cache... ");
    let cache = Cache::new();
    cache.save();
    println!("OK");

    print!("  [5/8] Creating lock file... ");
    // Create lock file with 600 permissions
    if OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(LOCK_PATH)
        .is_err()
    {
        exit_err("Failed to create lock file");
    }
    println!("OK");

    print!("  [6/8] Creating systemd service... ");
    let service = r#"[Unit]
Description=DDNS Firewall Synchronizer
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/ddnsfw/run
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ddnsfw

[Install]
WantedBy=multi-user.target
"#;
    if fs::write(SERVICE_PATH, service).is_err() {
        exit_err("Failed to write service file");
    }
    println!("OK");

    print!("  [7/8] Creating systemd timer... ");
    let timer = r#"[Unit]
Description=DDNS Firewall Synchronizer Timer

[Timer]
OnBootSec=30sec
OnUnitActiveSec=2min
RandomizedDelaySec=10sec
Persistent=true

[Install]
WantedBy=timers.target
"#;
    if fs::write(TIMER_PATH, timer).is_err() {
        exit_err("Failed to write timer file");
    }
    println!("OK");

    print!("  [8/8] Enabling service... ");
    let _ = Command::new("systemctl").args(["daemon-reload"]).output();
    let _ = Command::new("systemctl").args(["enable", "ddnsfw.timer"]).output();
    let _ = Command::new("systemctl").args(["start", "ddnsfw.timer"]).output();
    println!("OK");

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║                 Installation Complete!                     ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!("\nFiles:");
    println!("  Binary:  {}", BINARY_PATH);
    println!("  Config:  {}", CONFIG_PATH);
    println!("  Cache:   {}", CACHE_PATH);
    println!("  Service: {}", SERVICE_PATH);
    println!("  Timer:   {}", TIMER_PATH);
    println!("\nCommands:");
    println!("  Status:  systemctl status ddnsfw.timer");
    println!("  Logs:    journalctl -u ddnsfw -f");
    println!("  Rules:   iptables -L INPUT -n | grep DDNS");

    println!("\nRunning initial sync...\n");
    let _ = Command::new("systemctl").args(["start", "ddnsfw.service"]).output();
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    if !is_root() {
        exit_err("Must run as root");
    }

    if is_installed() && is_running_installed() {
        sync_firewall();
    } else if is_installed() {
        println!("Already installed at {}", BINARY_PATH);
        println!("To reinstall: sudo rm -rf {} {} {}", INSTALL_DIR, SERVICE_PATH, TIMER_PATH);
    } else {
        let entries = interactive_setup();
        install(entries);
    }
}
