use std::thread;
use std::time::{Duration, Instant, SystemTime};
use std::env;
use std::process::{Command, Stdio};
use std::fs;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::UNIX_EPOCH;

use daemonize::Daemonize;

const DEFAULT_TARGET_IP: &str = "127.0.0.1:80";
const PING_INTERVAL: u64 = 60; // 网络检查间隔60秒
const DAY_INTERVAL: u64 = 86400; // 网络检查间隔60秒
const CPU_CHECK_INTERVAL: u64 = 30; // CPU检查间隔30秒
// const ADBD_CHECK_INTERVAL: u64 = 60; // adbd检查间隔10秒
const MAX_FAILURES: u32 = 10;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_HIGH_LATENCY: u32 = 3;
const HIGH_LATENCY_THRESHOLD: u128 = 50; // 50ms

// CPU占用率监控配置
const CPU_USAGE_THRESHOLD: f32 = 85.0; // CPU占用率阈值 80%
// const HIGH_LOAD_CHECK_INTERVAL: u64 = 15; // 高负载时网络检查间隔（秒）
// const NORMAL_CHECK_INTERVAL: u64 = 30; // 正常负载时网络检查间隔（秒）

// UDP通知配置
// const UDP_SERVER: &str = DEFAULT_TARGET_IP; // UDP服务器地址
const UDP_LOCAL_BIND: &str = "0.0.0.0:0"; // 本地绑定地址
const UDP_TIMEOUT: Duration = Duration::from_secs(2); // UDP发送超时时间

// 信号监听配置
const SIGNAL_LISTEN_PORT: u16 = 1300; // 信号监听端口
const RESTART_SIGNAL_ADBD: &[u8] = b"RESTART_ADBD";
const KILL_SIGNAL_ADBD: &[u8] = b"KILL_ADBD"; 
const RESTART_SIGNAL_SERVER: &[u8] = b"RESTART_SERVER";
const SIGNAL_PING: &[u8] = b"PING";


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

#[repr(u8)]
#[derive(Copy, Clone)]
enum ServerCmd {
    None      = 0,
    RestartADB   = 1,
    KillADB      = 2,
    RestartSERVER   = 3,
}

impl ServerCmd {
    fn store(&self, atomic: &AtomicU8) {
        atomic.store(*self as u8, Ordering::Relaxed)
    }
    fn load(atomic: &AtomicU8) -> Self {
        match atomic.load(Ordering::Relaxed) {
            1 => ServerCmd::RestartADB,
            2 => ServerCmd::KillADB,
            3 => ServerCmd::RestartSERVER,
            _ => ServerCmd::None,
        }
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
        println!("Reboot after {} consecutive failures", MAX_FAILURES);
        println!("CPU usage threshold: {:.0}%", CPU_USAGE_THRESHOLD);
        println!("Usage: {} [TARGET_IP] [--background] [--isprod]", args[0]);
    }
    
    log_message(&format!("Network monitor started for {}", target_ip), is_prod);

    // 创建共享标志用于强制重启
    let server_cmd = Arc::new(AtomicU8::new(ServerCmd::None as u8));
    
    // 启动信号监听线程
    let server_cmd_clone = Arc::clone(&server_cmd);

    // let is_prod_signal = is_prod;
    // thread::spawn(move || {
    //     listen_for_signal(server_cmd_clone, is_prod_signal);
    // });
    let signal_sock = UdpSocket::bind(("0.0.0.0", SIGNAL_LISTEN_PORT))
                      .expect("bind signal port");
    signal_sock.set_nonblocking(true).expect("set_nonblocking");
    
    let mut failure_count = 0;
    let mut high_load_count = 0;
    let mut back_to_normal_load_count = 0;
    let mut high_latency_count = 0;
    let mut last_cpu_check = Instant::now();
    let mut last_network_check = Instant::now();
    // let mut last_udp_notification = Instant::now();
    // let mut last_adbd_check = Instant::now();
    let mut last_log_prune = Instant::now();
    
    // 初始化CPU统计
    let mut prev_cpu_stats = match get_cpu_stats() {
        Ok(stats) => stats,
        Err(e) => {
            log_message(&format!("Failed to get initial CPU stats: {}", e), is_prod);
            // 使用默认值继续运行
            CpuStats {
                user: 0, nice: 0, system: 0, idle: 0, iowait: 0,
                irq: 0, softirq: 0, steal: 0, guest: 0, guest_nice: 0,
            }
        }
    };

    thread::sleep(Duration::from_secs(30));
    optimize_network_parameters(is_prod);
    
    let mut buf = [0u8; 64];
    loop {
        let now = Instant::now();
        match signal_sock.recv_from(&mut buf) {
            Ok((size, src)) => {
                let received = &buf[..size];
                        
                if received == RESTART_SIGNAL_ADBD {
                    log_message(&format!("📨 Received restart signal from {}", src), is_prod);
                    ServerCmd::RestartADB.store(&server_cmd_clone);
                    // 发送确认响应
                    let _ = signal_sock.send_to(b"OK", src);
                } else if received == KILL_SIGNAL_ADBD {
                    log_message(&format!("📨 Received kill signal from {}", src), is_prod);
                    ServerCmd::KillADB.store(&server_cmd_clone);
                            
                    // 发送确认响应
                    let _ = signal_sock.send_to(b"OK", src);
                } else if received == RESTART_SIGNAL_SERVER {
                    log_message(&format!("📨 Received reboot signal from {}", src), is_prod);
                    ServerCmd::RestartSERVER.store(&server_cmd_clone);
                            
                    // 发送确认响应
                    let _ = signal_sock.send_to(b"OK", src);
                } else if received == SIGNAL_PING {
                    log_message(&format!("📨 Received ping signal from {}", src), is_prod);                            
                    let _ = signal_sock.send_to(b"OK", src);
                }
                // 清空缓冲区
                buf.fill(0);
            }
            Err(e) => {
                // if !is_prod {
                //     log_message(&format!("❌ Signal listener error: {}", e), is_prod);
                // }
            }
        }

        match ServerCmd::load(&server_cmd) {
            ServerCmd::RestartADB => {
                server_cmd.store(ServerCmd::None as u8, Ordering::Relaxed);
                match force_restart_adbd_process(is_prod) {
                    Ok(_) => {
                        log_message("✅ adbd force restarted successfully", is_prod);
                        send_udp_notification("ADBD_FORCE_RESTARTED", target_ip.clone(), is_prod);
                    }
                    Err(e) => {
                        log_message(&format!("❌ Failed to force restart adbd: {}", e), is_prod);
                    }
                }
            }
            ServerCmd::KillADB => {
                server_cmd.store(ServerCmd::None as u8, Ordering::Relaxed);
                match force_kill_adbd_process(is_prod) {
                    Ok(_) => {
                        log_message("✅ adbd force restarted successfully", is_prod);
                        send_udp_notification("ADBD_FORCE_KILLED", target_ip.clone(), is_prod);
                    }
                    Err(e) => {
                        log_message(&format!("❌ Failed to force restart adbd: {}", e), is_prod);
                    }
                }
            }
            ServerCmd::RestartSERVER => {
                server_cmd.store(ServerCmd::None as u8, Ordering::Relaxed);
                reboot_system(is_prod);
            }
            ServerCmd::None => {}
        }
        
        // CPU占用率检查 - 每30秒一次
        if now.duration_since(last_cpu_check) >= Duration::from_secs(CPU_CHECK_INTERVAL) {
            match get_cpu_stats() {
                Ok(current_cpu_stats) => {
                    let usage = calculate_cpu_usage(&prev_cpu_stats, &current_cpu_stats);
                    prev_cpu_stats = current_cpu_stats;
                    
                    if usage > CPU_USAGE_THRESHOLD {
                        if high_load_count == 0 {
                            log_message(&format!("High CPU usage detected: {:.1}%, entering high load mode", usage), is_prod);
                            high_load_count += 1;
                            // current_cpu_interval = HIGH_LOAD_CHECK_INTERVAL;
                            // 在高负载模式下，可以添加额外的保护措施
                            send_udp_notification(&format!("HIGH_LOAD_ENTER: CPU={:.1}%", usage), target_ip.clone(), is_prod);
                        } else {
                            log_message(&format!("High load mode active - CPU usage: {:.1}%", usage), is_prod);
                            high_load_count += 1;
                            send_udp_notification(&format!("HIGH_LOAD: CPU={:.1}%", usage), target_ip.clone(), is_prod);
                            if high_load_count == 3 {
                                throttle_network_parameters(is_prod);
                            }
                        }
                        back_to_normal_load_count = 0;
                        // last_udp_notification = now;
                        
                    } else {
                        if high_load_count > 0 {
                            log_message(&format!("CPU usage normalized: {:.1}%, returning to normal mode", usage), is_prod);

                            // current_cpu_interval = NORMAL_CHECK_INTERVAL;
                            back_to_normal_load_count += 1;
                            let mut restoreflag = false;

                            if back_to_normal_load_count >= 3 {
                                restoreflag = true;
                                high_load_count = 0;
                                back_to_normal_load_count = 0;
                            }
                            // 退出高负载模式时发送通知
                            send_udp_notification(&format!("HIGH_LOAD_EXIT: CPU={:.1}%", usage), target_ip.clone(), is_prod);

                            if restoreflag {
                                restore_network_parameters(is_prod);
                                clear_page_cache(is_prod);
                            }
                        } else {
                            //log_message(&format!("CPU usage normal: {:.1}%", usage), is_prod);
                        }
                    }
                }
                Err(e) => {
                    log_message(&format!("Failed to check CPU usage: {}", e), is_prod);
                }
            }
            last_cpu_check = now;
        }
        
        // 网络连通性检查 - 根据负载模式调整间隔
        if now.duration_since(last_network_check) >= Duration::from_secs(PING_INTERVAL) {
            match check_connectivity(&target_ip, is_prod) {
                (true, Some(connect_duration)) => {
                    if connect_duration.as_millis() > HIGH_LATENCY_THRESHOLD {
                        high_latency_count += 1;
                        log_message(&format!("High latency detected: {}ms (> {}ms)", connect_duration.as_millis(), HIGH_LATENCY_THRESHOLD), is_prod);
                        log_message(&format!("High latency count: {}/{}", high_latency_count, MAX_HIGH_LATENCY), is_prod);
                
                        if high_latency_count == MAX_HIGH_LATENCY {
                            log_message(&format!("WARN: {} consecutive high latency connections detected", MAX_HIGH_LATENCY), is_prod);
                            throttle_network_parameters(is_prod);
                        }
                    } else {
                        // 延迟正常时重置计数器
                        if high_latency_count == 3 {
                          restore_network_parameters(is_prod);
                        }
                        high_latency_count = 0;
                    }
                    failure_count = 0;
                }
                (true, None) => {
                    // 连接成功但没有获取到时间（理论上不应该发生，但需要处理）
                    log_message(&format!("✓ Connection to {} successful, but duration not measured", target_ip), is_prod);
                    high_latency_count = 0;
                    failure_count = 0;
                }
                (false, _) => {
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

       // adbd进程检查 - 每10秒一次
        // if now.duration_since(last_adbd_check) >= Duration::from_secs(ADBD_CHECK_INTERVAL) {
        //     match check_and_start_adbd(is_prod) {
        //         Ok(restarted) => {
        //             if restarted {
        //                 log_message("✅ adbd process was restarted", is_prod);
        //                 // 发送adbd重启通知
        //                 send_udp_notification("ADBD_RESTARTED", target_ip.clone() ,is_prod);
        //             }
        //         }
        //         Err(e) => {
        //             log_message(&format!("❌ adbd check failed: {}", e), is_prod);
        //         }
        //     }
        //     last_adbd_check = now;
        // }

        if now.duration_since(last_log_prune) >= Duration::from_secs(DAY_INTERVAL) {
            if let Err(e) = fs::write("/etc_rw/zxping.log", "") {
                log_message(&format!("Failed to clear zxping.log: {}", e), is_prod);
            } else {
                log_message("zxping.log cleared", is_prod);
            }
            last_log_prune = now;
        }

        // 睡眠1秒后继续检查，避免忙等待
        thread::sleep(Duration::from_secs(2));
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
        //"echo 100 > /proc/sys/net/ipv4/tcp_max_syn_backlog",

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
        "echo 10 > /proc/sys/net/ipv4/tcp_retries2",
        "echo 600 > /proc/sys/net/ipv4/tcp_keepalive_time",
        "echo 10 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_time_wait",
        "echo 1800 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established",
        "echo 4800 > /proc/sys/net/nf_conntrack_max",
    ];



    for cmd in commands.iter() {
        thread::sleep(Duration::from_millis(200));
        if let Err(e) = Command::new("sh").arg("-c").arg(cmd).status() {
            if !is_prod {
                log_message(&format!("Failed to adjust network parameter {}: {}", cmd, e), is_prod);
            }
        }
    }
}
// fn get_br_ip_address(is_prod: bool) -> String {
//     // 方法1: 使用 ip 命令获取 wan1 接口的 IP
//     if let Ok(output) = Command::new("ip")
//         .args(["addr", "show", "br0"])
//         .output() 
//     {
//         if output.status.success() {
//             let output_str = String::from_utf8_lossy(&output.stdout);
//             for line in output_str.lines() {
//                 if line.trim().starts_with("inet ") {
//                     let parts: Vec<&str> = line.trim().split_whitespace().collect();
//                     if parts.len() >= 2 {
//                         let ip_with_mask = parts[1];
//                         if let Some(ip) = ip_with_mask.split('/').next() {
//                             if !ip.is_empty() && ip != "127.0.0.1" {
//                                 log_message(&format!("Found wan1 IP via ip command: {}", ip), is_prod);
//                                 return ip.to_string();
//                             }
//                         }
//                     }
//                 }
//             }
//         }
//     }

//     log_message("Could not determine wan1 IP address", is_prod);
//     String::new()
// }

fn get_br_network(is_prod: bool) -> String {
    // 获取 br0 接口的网络地址 (如 192.168.0.0/24)
    if let Ok(output) = Command::new("ip")
        .args(["route", "show", "dev", "br0"])
        .output() 
    {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                // 查找类似 "192.168.0.0/24" 的网络路由
                if parts.len() >= 1 && parts[0].contains('/') {
                    let network = parts[0];
                    if network != "default" && !network.starts_with("169.254") {
                        log_message(&format!("Found br0 network: {}", network), is_prod);
                        return network.to_string();
                    }
                }
            }
        }
    }

    // 如果无法获取网络地址，使用默认的 192.168.0.0/24
    log_message("Could not determine br0 network, using default 192.168.0.0/24", is_prod);
    "192.168.0.0/24".to_string()
}

fn optimize_network_parameters(is_prod: bool) {
    // 调整TCP参数来减轻网络栈负担
    let br_network = get_br_network(is_prod);

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

        //"echo 0 > /proc/sys/net/ipv4/tcp_window_scaling"
    ];

    if !br_network.is_empty() {
        let ipt_cmds = [
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT",
            "iptables -P OUTPUT ACCEPT",
            "iptables -F -t filter",
            "iptables -F -t nat",
            // "iptables -t nat -A POSTROUTING -s 192.168.0.2/32 -o wan1 -j MASQUERADE",
            &format!("iptables -t nat -A POSTROUTING -s {} -o wan1 -j MASQUERADE", br_network),
            "ip6tables -F",
             //&format!("iptables -t nat -I POSTROUTING -s 192.168.0.2/32 -o wan1 -j SNAT --to-source {}", wan1_ip)
        ];
        for cmd in ipt_cmds.iter() {
            if let Err(e) = Command::new("sh").arg("-c").arg(cmd).status() {
                if !is_prod {
                    log_message(&format!("Failed to adjust network parameter {}: {}", cmd, e), is_prod);
                }
            }
        }
    }

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
        // .open("/etc_rw/zxping.log")
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

fn check_connectivity(target_ip: &str, is_prod: bool) -> (bool, Option<std::time::Duration>) {
    let start = Instant::now();
    
    match tcp_connect_check(target_ip, is_prod) {
        true => {
            let duration = start.elapsed();
            (true, Some(duration))
        }
        false => (false, None)
    }
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
    // thread::sleep(Duration::from_secs(PING_INTERVAL));
}


fn send_udp_notification(message: &str, addr: String, is_prod: bool) {
    // 获取设备标识（可以使用主机名或自定义标识）
    // let hostname = get_hostname().unwrap_or_else(|_| "unknown".to_string());
    // let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    let full_message = format!("[{}] {}", "zxic", message);
    
    match UdpSocket::bind(UDP_LOCAL_BIND) {
        Ok(socket) => {
            // 设置超时时间
            let _ = socket.set_write_timeout(Some(UDP_TIMEOUT));
            
            match socket.send_to(full_message.as_bytes(), addr) {
                Ok(_) => {
                    if !is_prod {
                        log_message(&format!("UDP notification sent: {}", full_message), is_prod);
                    }
                }
                Err(e) => {
                    if !is_prod {
                        log_message(&format!("Failed to send UDP notification: {}", e), is_prod);
                    }
                }
            }
        }
        Err(e) => {
            if !is_prod {
                log_message(&format!("Failed to create UDP socket: {}", e), is_prod);
            }
        }
    }
}

fn log_message(message: &str, is_prod: bool) {
    if !is_prod {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let timestamp = duration.as_secs();
        println!("[{}] {}", timestamp, message);
    }
}
 
// 监听重启信号的轻量级UDP服务器
// fn listen_for_signal(cmd: Arc<AtomicU8>, is_prod: bool) {
//     match UdpSocket::bind(("0.0.0.0", SIGNAL_LISTEN_PORT)) {
//         Ok(socket) => {
//             log_message(&format!("📡 Signal listener started on port {}", SIGNAL_LISTEN_PORT), is_prod);
            
//             let mut buf = [0u8; 64];
            
//             loop {
//                 match socket.recv_from(&mut buf) {
//                     Ok((size, src)) => {
//                         let received = &buf[..size];
                        
//                         if received == RESTART_SIGNAL_ADBD {
//                             log_message(&format!("📨 Received restart signal from {}", src), is_prod);
//                             ServerCmd::RestartADB.store(&cmd);
//                             // 发送确认响应
//                             let _ = socket.send_to(b"OK", src);
//                         }
//                         if received == KILL_SIGNAL_ADBD {
//                             log_message(&format!("📨 Received kill signal from {}", src), is_prod);
//                             ServerCmd::KillADB.store(&cmd);
                            
//                             // 发送确认响应
//                             let _ = socket.send_to(b"OK", src);
//                         }
//                     }
//                     Err(e) => {
//                         if !is_prod {
//                             log_message(&format!("❌ Signal listener error: {}", e), is_prod);
//                         }
//                     }
//                 }
                
//                 // 清空缓冲区
//                 buf.fill(0);
//             }
//         }
//         Err(e) => {
//             log_message(&format!("❌ Failed to start signal listener: {}", e), is_prod);
//         }
//     }
// }


// 强制重启adbd进程
fn force_restart_adbd_process(is_prod: bool) -> Result<(), String> {
    log_message("Force restart adbd process...", is_prod);
    
    // 1. 查找并杀死所有adbd进程
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            
            if name_str.chars().all(|c| c.is_ascii_digit()) {
                let cmdline_path = format!("/proc/{}/cmdline", name_str);
                if let Ok(cmdline_content) = fs::read_to_string(&cmdline_path) {
                    if cmdline_content.contains("adbd") {
                        // 修复：将 Cow<'_, str> 转换为 String
                        let pid = name_str.to_string();
                        // 杀死adbd进程
                        let _ = Command::new("/bin/kill")
                            .arg("-9")
                            .arg(&pid)
                            .status();
                        log_message(&format!("Killed adbd process (PID: {})", pid), is_prod);
                    }
                }
            }
        }
    }
    
    // 2. 等待一段时间确保进程完全终止
    thread::sleep(Duration::from_secs(3));
    
    // 3. 启动新的adbd进程
    let status = Command::new("/bin/adbd")
        .stdout(Stdio::null())  // 标准输出重定向到 /dev/null
        .stderr(Stdio::null())  // 标准错误重定向到 /dev/null
        .status()
        .map_err(|e| format!("Failed to start adbd: {}", e));
        // .or_else(|_| {
        //     Command::new("/bin/adbd")
        //         .stdout(Stdio::null())  // 标准输出重定向到 /dev/null
        //         .stderr(Stdio::null())  // 标准错误重定向到 /dev/null
        //         .status()
        //         .map_err(|e| format!("Failed to start adbd: {}", e))
        // });
    
    match status {
        Ok(_) => {
            log_message("adbd force restarted successfully", is_prod);
            Ok(())
        }
        Err(e) => {
            Err(format!("Failed to force restart adbd: {}", e))
        }
    }
}

// 同时修复 check_and_start_adbd 函数中的相同问题
// fn check_and_start_adbd(is_prod: bool) -> Result<bool, String> {
//     let mut adbd_found = false;
//     let mut adbd_pid = String::new();

//     if let Ok(entries) = fs::read_dir("/proc") {
//         for entry in entries.flatten() {
//             let file_name = entry.file_name();
//             let name_str = file_name.to_string_lossy();
            
//             if name_str.chars().all(|c| c.is_ascii_digit()) {
//                 let cmdline_path = format!("/proc/{}/cmdline", name_str);
//                 if let Ok(cmdline_content) = fs::read_to_string(&cmdline_path) {
//                     if cmdline_content.contains("adbd") {
//                         adbd_found = true;
//                         // 修复：将 Cow<'_, str> 转换为 String
//                         adbd_pid = name_str.to_string();
                        
//                         let stat_path = format!("/proc/{}/stat", adbd_pid);
//                         if let Ok(stat_content) = fs::read_to_string(&stat_path) {
//                             let parts: Vec<&str> = stat_content.split_whitespace().collect();
//                             if parts.len() > 2 {
//                                 let state = parts[2];
//                                 if state == "R" || state == "S" {
//                                     if !is_prod {
//                                         log_message(&format!("adbd is running (PID: {}, State: {})", adbd_pid, state), is_prod);
//                                     }
//                                     return Ok(false);
//                                 } else {
//                                     log_message(&format!("adbd process exists but state is {} (not running properly)", state), is_prod);
//                                     continue;
//                                 }
//                             }
//                         }
//                         break;
//                     }
//                 }
//             }
//         }
//     } else {
//         return Err("Failed to read /proc directory".to_string());
//     }

//     if adbd_found {
//         log_message(&format!("adbd process (PID: {}) exists but not in running state, attempting to restart...", adbd_pid), is_prod);
        
//         // 修复：这里也需要转换
//         if let Ok(_) = Command::new("kill")
//             .arg("-9")
//             .arg(&adbd_pid)
//             .status() 
//         {
//             log_message(&format!("Killed abnormal adbd process (PID: {})", adbd_pid), is_prod);
//             thread::sleep(Duration::from_secs(1));
//         }
//     } else {
//         log_message("adbd not found in /proc, attempting to start...", is_prod);
//     }
    
//     let status = Command::new("adbd")
//         .stdout(Stdio::null())  // 标准输出重定向到 /dev/null
//         .stderr(Stdio::null())  // 标准错误重定向到 /dev/null
//         .status()
//         .or_else(|_| {
//             Command::new("/bin/adbd")
//                 .stdout(Stdio::null())  // 标准输出重定向到 /dev/null
//                 .stderr(Stdio::null())  // 标准错误重定向到 /dev/null
//                 .status()
//                 .map_err(|e| format!("Failed to start adbd: {}", e))
//         });
    
//     match status {
//         Ok(_) => {
//             log_message("adbd started successfully", is_prod);
//             Ok(true)
//         }
//         Err(e) => {
//             Err(format!("Failed to start adbd: {}", e))
//         }
//     }
// }



// 强制重启adbd进程
fn force_kill_adbd_process(is_prod: bool) -> Result<(), String> {
    log_message("Force restarting adbd process...", is_prod);
    
     // 1. 查找并杀死所有adbd进程
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            
            if name_str.chars().all(|c| c.is_ascii_digit()) {
                let cmdline_path = format!("/proc/{}/cmdline", name_str);
                if let Ok(cmdline_content) = fs::read_to_string(&cmdline_path) {
                    if cmdline_content.contains("adbd") {
                        // 修复：将 Cow<'_, str> 转换为 String
                        let pid = name_str.to_string();
                        // 杀死adbd进程
                        let _ = Command::new("kill")
                            .arg("-9")
                            .arg(&pid)
                            .status();
                        log_message(&format!("Killed adbd process (PID: {})", pid), is_prod);
                    }
                }
            }
        }
    }
    
    // 2. 等待一段时间确保进程完全终止
    thread::sleep(Duration::from_secs(1));

    return Ok(())
}