use std::thread;
use std::time::{Duration, Instant};
use std::env;
use std::process::Command;
use std::fs;
use daemonize::Daemonize;

const DEFAULT_TARGET_IP: &str = "127.0.0.1:80";
const PING_INTERVAL: u64 = 60; // 网络检查间隔60秒
const CPU_CHECK_INTERVAL: u64 = 30; // CPU检查间隔30秒
const MAX_FAILURES: u32 = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

// CPU占用率监控配置
const CPU_USAGE_THRESHOLD: f32 = 95.0; // CPU占用率阈值 80%
const HIGH_LOAD_CHECK_INTERVAL: u64 = 30; // 高负载时网络检查间隔（秒）
const NORMAL_CHECK_INTERVAL: u64 = 60; // 正常负载时网络检查间隔（秒）

#[derive(Debug, Clone)]
struct CpuStats {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
    guest: u64,
    guest_nice: u64,
}

impl CpuStats {
    fn total(&self) -> u64 {
        self.user + self.nice + self.system + self.idle + self.iowait +
        self.irq + self.softirq + self.steal + self.guest + self.guest_nice
    }
    
    fn idle_total(&self) -> u64 {
        self.idle + self.iowait
    }
    
    fn active_total(&self) -> u64 {
        self.total() - self.idle_total()
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // 检查是否需要后台运行
    if args.iter().any(|arg| arg == "--background" || arg == "-b") {
        daemonize_simple();
    }
    let mut is_prod = false;
    if args.iter().any(|arg| arg == "--isprod") {
       is_prod = true;
    }
    
    let target_ip = get_target_ip();
    
    if !is_prod {
        println!("Network monitor started for {}", target_ip);
        println!("Network check interval: {} seconds", PING_INTERVAL);
        println!("CPU check interval: {} seconds", CPU_CHECK_INTERVAL);
        println!("Reboot after {} consecutive failures", MAX_FAILURES);
        println!("CPU usage threshold: {:.0}%", CPU_USAGE_THRESHOLD);
        println!("High load network check interval: {} seconds", HIGH_LOAD_CHECK_INTERVAL);
        println!("Usage: {} [TARGET_IP] [--background] [--isprod]", args[0]);
    }
    
    log_message(&format!("Network monitor started for {}", target_ip), is_prod);
    
    let mut failure_count = 0;
    let mut current_network_interval = NORMAL_CHECK_INTERVAL;
    let mut high_load_mode = false;
    let mut last_cpu_check = Instant::now();
    let mut last_network_check = Instant::now();
    
    // 初始化CPU统计
    let mut prev_cpu_stats = match get_cpu_stats() {
        Ok(stats) => stats,
        Err(e) => {
            log_message(&format!("❌ Failed to get initial CPU stats: {}", e), is_prod);
            // 使用默认值继续运行
            CpuStats {
                user: 0, nice: 0, system: 0, idle: 0, iowait: 0,
                irq: 0, softirq: 0, steal: 0, guest: 0, guest_nice: 0,
            }
        }
    };
    restore_network_parameters(is_prod);
    
    loop {
        let now = Instant::now();
        
        // CPU占用率检查 - 每30秒一次
        if now.duration_since(last_cpu_check) >= Duration::from_secs(CPU_CHECK_INTERVAL) {
            match get_cpu_stats() {
                Ok(current_cpu_stats) => {
                    let usage = calculate_cpu_usage(&prev_cpu_stats, &current_cpu_stats);
                    prev_cpu_stats = current_cpu_stats;
                    
                    if usage > CPU_USAGE_THRESHOLD {
                        if !high_load_mode {
                            log_message(&format!("⚠️ High CPU usage detected: {:.1}%, entering high load mode", usage), is_prod);
                            high_load_mode = true;
                            current_network_interval = HIGH_LOAD_CHECK_INTERVAL;
                        }
                        log_message(&format!("High load mode active - CPU usage: {:.1}%, network check interval: {}s", usage, current_network_interval), is_prod);
                        
                        // 在高负载模式下，可以添加额外的保护措施
                        throttle_network_parameters(is_prod);
                        
                    } else {
                        if high_load_mode {
                            log_message(&format!("✅ CPU usage normalized: {:.1}%, returning to normal mode", usage), is_prod);
                            high_load_mode = false;
                            current_network_interval = NORMAL_CHECK_INTERVAL;

                            restore_network_parameters(is_prod);
                            clear_page_cache(is_prod);

                        } else {
                            log_message(&format!("CPU usage normal: {:.1}%", usage), is_prod);
                        }
                    }
                }
                Err(e) => {
                    log_message(&format!("❌ Failed to check CPU usage: {}", e), is_prod);
                }
            }
            last_cpu_check = now;
        }
        
        // 网络连通性检查 - 根据负载模式调整间隔
        if now.duration_since(last_network_check) >= Duration::from_secs(current_network_interval) {
            match check_connectivity(&target_ip, is_prod) {
                true => {
                    log_message(&format!("✓ Connection to {} successful", target_ip), is_prod);
                    failure_count = 0;
                }
                false => {
                    log_message(&format!("✗ Connection to {} failed", target_ip), is_prod);
                    failure_count += 1;
                    log_message(&format!("Failure count: {}/{}", failure_count, MAX_FAILURES), is_prod);
                    
                    if failure_count >= MAX_FAILURES {
                        log_message(&format!("Critical: {} consecutive failures detected", MAX_FAILURES), is_prod);
                        log_message("Initiating system reboot...", is_prod);
                        reboot_system(is_prod);
                    }
                }
            }
            last_network_check = now;
        }
        // 睡眠1秒后继续检查，避免忙等待
        thread::sleep(Duration::from_secs(3));
    }
}

fn get_cpu_stats() -> Result<CpuStats, String> {
    let stat_content = fs::read_to_string("/proc/stat")
        .map_err(|e| format!("Failed to read /proc/stat: {}", e))?;
    
    // 查找第一行（总CPU统计）
    for line in stat_content.lines() {
        if line.starts_with("cpu ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                return Ok(CpuStats {
                    user: parts[1].parse().unwrap_or(0),
                    nice: parts[2].parse().unwrap_or(0),
                    system: parts[3].parse().unwrap_or(0),
                    idle: parts[4].parse().unwrap_or(0),
                    iowait: parts[5].parse().unwrap_or(0),
                    irq: parts[6].parse().unwrap_or(0),
                    softirq: parts[7].parse().unwrap_or(0),
                    steal: parts[8].parse().unwrap_or(0),
                    guest: parts[9].parse().unwrap_or(0),
                    guest_nice: parts.get(10).and_then(|s| s.parse().ok()).unwrap_or(0),
                });
            }
        }
    }
    
    Err("Cannot find CPU statistics in /proc/stat".to_string())
}

fn calculate_cpu_usage(prev: &CpuStats, current: &CpuStats) -> f32 {
    let prev_active = prev.active_total();
    let prev_total = prev.total();
    
    let current_active = current.active_total();
    let current_total = current.total();
    
    // 计算增量
    let active_delta = current_active as i64 - prev_active as i64;
    let total_delta = current_total as i64 - prev_total as i64;
    
    if total_delta > 0 {
        (active_delta as f32 / total_delta as f32) * 100.0
    } else {
        0.0
    }
}

fn throttle_network_parameters(is_prod: bool) {
    // 调整TCP参数来减轻网络栈负担
    let commands = [
        "echo 800 > /proc/sys/net/core/netdev_max_backlog",
        "echo 3000 > /proc/sys/net/unix/max_dgram_qlen",
        "echo 100 > /proc/sys/net/ipv4/tcp_max_syn_backlog",

        "echo 5 > /proc/sys/net/ipv4/tcp_retries2",
        "echo 300 > /proc/sys/net/ipv4/tcp_keepalive_time",
        "echo 5 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_time_wait",
        "echo 900 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established",
        "echo 3800 > /proc/sys/net/nf_conntrack_max",
    ];
    for cmd in commands.iter() {
        if let Err(e) = Command::new("sh").arg("-c").arg(cmd).status() {
            if !is_prod {
                log_message(&format!("Failed to adjust network parameter {}: {}", cmd, e), is_prod);
            }
        }
    }
}

fn restore_network_parameters(is_prod: bool) {
    // 调整TCP参数来减轻网络栈负担
    let commands = [
        "echo 1000 > /proc/sys/net/core/netdev_max_backlog",
        "echo 5000 > /proc/sys/net/unix/max_dgram_qlen",
        "echo 128 > /proc/sys/net/ipv4/tcp_max_syn_backlog",

        "echo 10 > /proc/sys/net/ipv4/tcp_retries2",
        "echo 15 > /proc/sys/net/ipv4/tcp_fin_timeout",
        "echo 600 > /proc/sys/net/ipv4/tcp_keepalive_time",
        "echo 10 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_time_wait",
        "echo 1800 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established",
        "echo 15 > /proc/sys/net/ipv4/netfilter/ip_conntrack_udp_timeout",
        "echo 10 > /proc/sys/net/ipv4/netfilter/ip_conntrack_udp_timeout_stream",
        "echo 20 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_close",
        "echo 4800 > /proc/sys/net/nf_conntrack_max",
    ];
    for cmd in commands.iter() {
        if let Err(e) = Command::new("sh").arg("-c").arg(cmd).status() {
            if !is_prod {
                log_message(&format!("Failed to adjust network parameter {}: {}", cmd, e), is_prod);
            }
        }
    }
}

fn clear_page_cache(is_prod: bool) {
    // 清理页面缓存（需要root权限）
    if let Err(e) = Command::new("sh")
        .arg("-c")
        .arg("echo 1 > /proc/sys/vm/drop_caches")
        .status() 
    {
        log_message(&format!("Failed to clear page cache: {}", e), is_prod);
    } else {
        log_message("Page cache cleared", is_prod);
    }
}

fn daemonize_simple() {
    let dev_null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .expect("cannot open /dev/null");

    Daemonize::new()
        .stdout(dev_null.try_clone().unwrap())
        .stderr(dev_null)
        .start()
        .expect("daemonize failed");
}

fn get_target_ip() -> String {
    let args: Vec<String> = env::args().collect();
    
    for arg in &args[1..] {
        if !arg.starts_with("--") {
            return arg.clone();
        }
    }
    
    if let Ok(env_ip) = env::var("TARGET_IP") {
        if !env_ip.is_empty() {
            return env_ip;
        }
    }
    
    DEFAULT_TARGET_IP.to_string()
}

fn check_connectivity(target_ip: &str, is_prod: bool) -> bool {
    tcp_connect_check(target_ip, is_prod)
}

fn tcp_connect_check(target_ip: &str, is_prod: bool) -> bool {
    use std::net::TcpStream;
    
    let start = Instant::now();
    
    match TcpStream::connect_timeout(
        &target_ip.parse().unwrap(),
        CONNECT_TIMEOUT
    ) {
        Ok(_) => {
            let duration = start.elapsed();
            if !is_prod {
                log_message(&format!("TCP connect successful, took {:?}", duration), is_prod);
            }
            true
        }
        Err(e) => {
            log_message(&format!("TCP connect failed: {}", e), is_prod);
            false
        }
    }
}

fn reboot_system(is_prod: bool) {
    log_message("Attempting system reboot...", is_prod);
    
    let _ = Command::new("/sbin/reboot").status();
    
    log_message("All reboot attempts failed! Continuing monitoring...", is_prod);
    thread::sleep(Duration::from_secs(PING_INTERVAL));
}

fn log_message(message: &str, is_prod: bool) {
    if !is_prod {
        println!("{}", message);
    }
}