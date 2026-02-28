use std::thread;
use std::time::{Duration, Instant, SystemTime};
use std::env;
use std::process::{Command, Stdio};
use std::fs::{self, File};
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicBool, Ordering};
use std::time::UNIX_EPOCH;
use std::net::SocketAddr;
use std::io::{self, BufRead, BufReader};
use std::os::unix::io::AsRawFd;

use libc::{self, c_int};

use daemonize::Daemonize;

const DEFAULT_TARGET_IP: &str = "127.0.0.1:80";
const PING_INTERVAL: u64 = 60; // 网络检查间隔60秒
const DAY_INTERVAL: u64 = 86400; // 网络检查间隔60秒
const SNAT_CHECK_INTERVAL: u64 = 300; // CPU检查间隔30秒
const USB_HEALTH_CHECK_INTERVAL: u64 = 10; // USB健康检查间隔10秒
const USB_WARNING_THRESHOLD: u32 = 3; // USB警告阈值
const USB_CRITICAL_THRESHOLD: u32 = 2; // USB危险阈值
// const ADBD_CHECK_INTERVAL: u64 = 60; // adbd检查间隔10秒
const WARN_FAILURES: u32 = 10;
const MAX_FAILURES: u32 = 15;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_HIGH_LATENCY: u32 = 3;
const HIGH_LATENCY_THRESHOLD: u128 = 300; // 50ms
const HIGH_LATENCY_THRESHOLD_MIN: u128 = 100; // 50ms
const HIGH_LATENCY_THRESHOLD_MAX: u128 = 2000; // 50ms

// CPU占用率监控配置
// const CPU_USAGE_THRESHOLD: f32 = 85.0; // CPU占用率阈值 80%
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
const DISABLE_ADB: &[u8] = b"DISABLE_ADB";
const RESTART_SIGNAL_SERVER: &[u8] = b"RESTART_SERVER";
const RESTART_SIGNAL_GOAHEAD: &[u8] = b"RESTART_GOAHEAD";
const REDUCE_KERNEL_LOAD: &[u8] = b"REDUCE_KERNEL_LOAD";
const SIGNAL_PING: &[u8] = b"PING";
const ENABLE_KMSG_MONITOR: &[u8] = b"ENABLE_KMSG_MONITOR";
const DISABLE_KMSG_MONITOR: &[u8] = b"DISABLE_KMSG_MONITOR";

// KMSG 监控配置
const KMSG_CHECK_INTERVAL: Duration = Duration::from_millis(1000); // KMSG检查间隔100ms
const KMSG_PANIC_KEYWORDS: &[&str] = &[
    "error",
    "overflow",
    "panic",
    "hung",
    "fault",
    "unable",
    "memory",
    "Call Trace",
    "overflow",
    "corrupted",
    "warn",
    "lock",
    "blocked",
];

// echo -n "REDUCE_KERNEL_LOAD" | nc -u <TARGETIP> 1300


#[repr(u8)]
#[derive(Copy, Clone)]
enum ServerCmd {
    None      = 0,
    RestartADB   = 1,
    KillADB      = 2,
    RestartSERVER   = 3,
    DisableADB   = 4,
    RestartGoAhead = 5,
    ReduceKernelLoad = 6,
    EnableKmsgMonitor = 7,
    DisableKmsgMonitor = 8,
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
            4 => ServerCmd::DisableADB,
            5 => ServerCmd::RestartGoAhead,
            6 => ServerCmd::ReduceKernelLoad,
            7 => ServerCmd::EnableKmsgMonitor,
            8 => ServerCmd::DisableKmsgMonitor,
            _ => ServerCmd::None,
        }
    }
}

/// KMSG 监控状态 - 极简内存设计，无线程
struct KmsgMonitor {
    enabled: AtomicBool,
    reader: Option<BufReader<File>>,
    last_warning_time: Option<Instant>,
}

impl KmsgMonitor {
    fn new() -> Self {
        KmsgMonitor {
            enabled: AtomicBool::new(false),
            reader: None,
            last_warning_time: None,
        }
    }

    fn enable(&mut self, is_prod: bool) {
        if !self.enabled.load(Ordering::Relaxed) {
            // 尝试打开 /proc/kmsg
            match File::open("/proc/kmsg") {
                Ok(file) => {
                    // 设置为非阻塞模式
                    unsafe {
                        let fd = file.as_raw_fd();
                        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                        if flags >= 0 {
                            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                        }
                    }
                    self.reader = Some(BufReader::new(file));
                    self.enabled.store(true, Ordering::Relaxed);
                    log_message("KMSG monitor enabled", is_prod);
                }
                Err(e) => {
                    log_message(&format!("Failed to open /proc/kmsg: {}", e), is_prod);
                }
            }
        }
    }

    fn disable(&mut self, is_prod: bool) {
        if self.enabled.load(Ordering::Relaxed) {
            self.enabled.store(false, Ordering::Relaxed);
            self.reader = None;
            log_message("KMSG monitor disabled", is_prod);
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// 在主循环中调用，检查 KMSG
    fn check(&mut self, target_ip: &str, is_prod: bool) {
        if !self.is_enabled() {
            return;
        }

        const WARNING_COOLDOWN: Duration = Duration::from_secs(5);
        let reader = match &mut self.reader {
            Some(r) => r,
            None => return,
        };

        // 尽可能多地读取行（非阻塞）
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break, // 没有更多数据
                Ok(_) => {
                    // 检查是否包含崩溃关键词
                    if let Some(keyword) = Self::check_panic_keywords(&line) {
                        let now = Instant::now();
                        let should_warn = match self.last_warning_time {
                            Some(t) if now.duration_since(t) >= WARNING_COOLDOWN => true,
                            None => true,
                            _ => false,
                        };

                        if should_warn {
                            let warning_msg = format!(
                                "KERNEL_WARNING: detected '{}' in kmsg: {}",
                                keyword,
                                line.trim().chars().take(200).collect::<String>()
                            );
                            log_message(&warning_msg, is_prod);
                            send_udp_notification(&warning_msg, target_ip.to_string(), is_prod);
                            self.last_warning_time = Some(now);
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        break; // 没有更多数据可读
                    }
                    // 其他错误，记录但不影响主循环
                    break;
                }
            }
        }
    }

    /// 检查行中是否包含崩溃关键词
    fn check_panic_keywords(line: &str) -> Option<&str> {
        for keyword in KMSG_PANIC_KEYWORDS {
            if line.contains(keyword) {
                return Some(keyword);
            }
        }
        None
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // 检查是否需要后台运行
    let mut is_prod = false;
    if args.iter().any(|arg| arg == "--isprod") {
       is_prod = true;
    }
    if args.iter().any(|arg| arg == "--background" || arg == "-b") {
        daemonize_simple(is_prod);
    }
    
    let target_ip = get_target_ip();
    
    if !is_prod {
        println!("Network monitor started for {}", target_ip);
        println!("Network check interval: {} seconds", PING_INTERVAL);
        println!("Reboot after {} consecutive failures", MAX_FAILURES);
        println!("Usage: {} [TARGET_IP] [--background] [--isprod]", args[0]);
    }
    
    let target_sock_ip = match target_ip.parse::<SocketAddr>() {
        Ok(sock) => sock.ip().to_string(),
        Err(_)   => {
            log_message(&format!("invalid target_ip: {}", target_ip), is_prod);
            return;
        }
    };
    log_message(&format!("Network monitor started for {}", target_ip), is_prod);

    // 创建共享标志用于强制重启
    let server_cmd = Arc::new(AtomicU8::new(ServerCmd::None as u8));
    
    // 创建 KMSG 监控器（极简设计，无线程）
    let mut kmsg_monitor = KmsgMonitor::new();
    
    // 启动信号监听
    let server_cmd_clone = Arc::clone(&server_cmd);

    let signal_sock = UdpSocket::bind(("0.0.0.0", SIGNAL_LISTEN_PORT))
                      .expect("bind signal port");
    signal_sock.set_nonblocking(true).expect("set_nonblocking");
    
    let mut failure_count = 0;
    let mut high_latency_count = 0;
    let mut last_network_check = Instant::now();
    let mut last_snat_check = Instant::now();
    // let mut last_udp_notification = Instant::now();
    // let mut last_adbd_check = Instant::now();
    let mut last_log_prune = Instant::now();
    
    thread::sleep(Duration::from_secs(30));
    optimize_network_parameters(is_prod, target_ip.clone());
    force_kill_process(is_prod, "dnsmasq");
    // force_kill_process(is_prod, "goahead");
    // match force_start_goahead_process(is_prod) {
    //     Ok(_) => {
    //         log_message("✅ gohead force restarted successfully", is_prod);
    //     }
    //     Err(e) => {
    //         log_message(&format!("❌ Failed to force restart gohead: {}", e), is_prod);
    //     }
    // }
    
    loop {
        let now = Instant::now();
        let mut buf = [0u8; 64];
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
                } else if received == DISABLE_ADB {
                    log_message(&format!("📨 Received disable adb signal from {}", src), is_prod);
                    ServerCmd::DisableADB.store(&server_cmd_clone);
                            
                    // 发送确认响应
                    let _ = signal_sock.send_to(b"OK", src);
                } else if received == RESTART_SIGNAL_SERVER {
                    log_message(&format!("📨 Received reboot signal from {}", src), is_prod);
                    ServerCmd::RestartSERVER.store(&server_cmd_clone);
                            
                    // 发送确认响应
                    let _ = signal_sock.send_to(b"OK", src);
                } else if received == RESTART_SIGNAL_GOAHEAD {
                    log_message(&format!("📨 Received restart goahead signal from {}", src), is_prod);
                    ServerCmd::RestartGoAhead.store(&server_cmd_clone);
                            
                    // 发送确认响应
                    let _ = signal_sock.send_to(b"OK", src);
                } else if received == REDUCE_KERNEL_LOAD {
                    log_message(&format!("📨 Received reduce kernel load signal from {}", src), is_prod);
                    ServerCmd::ReduceKernelLoad.store(&server_cmd_clone);
                            
                    // 发送确认响应
                    let _ = signal_sock.send_to(b"OK", src);
                } else if received == ENABLE_KMSG_MONITOR {
                    log_message(&format!("📨 Received enable kmsg monitor signal from {}", src), is_prod);
                    ServerCmd::EnableKmsgMonitor.store(&server_cmd_clone);
                    
                    // 发送确认响应
                    let _ = signal_sock.send_to(b"OK", src);
                } else if received == DISABLE_KMSG_MONITOR {
                    log_message(&format!("📨 Received disable kmsg monitor signal from {}", src), is_prod);
                    ServerCmd::DisableKmsgMonitor.store(&server_cmd_clone);
                    
                    // 发送确认响应
                    let _ = signal_sock.send_to(b"OK", src);
                } else if received == SIGNAL_PING {
                    // log_message(&format!("📨 Received ping signal from {}", src), is_prod);                            
                    let _ = signal_sock.send_to(b"OK", src);
                }
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
                match force_kill_process(is_prod, "adbd") {
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
            ServerCmd::DisableADB => {
                server_cmd.store(ServerCmd::None as u8, Ordering::Relaxed);
                match disable_adb_function(is_prod) {
                    Ok(_) => {
                        log_message("✅ adb function disabled successfully", is_prod);
                        send_udp_notification("ADB_FUNCTION_DISABLED", target_ip.clone(), is_prod);
                    }
                    Err(e) => {
                        log_message(&format!("❌ Failed to disable adb function: {}", e), is_prod);
                    }
                }
            }
            ServerCmd::RestartGoAhead => {
                server_cmd.store(ServerCmd::None as u8, Ordering::Relaxed);
                match force_start_goahead_process(is_prod) {
                    Ok(_) => {
                        log_message("✅ goahead force restarted successfully", is_prod);
                        send_udp_notification("GOAHEAD_FORCE_RESTARTED", target_ip.clone(), is_prod);
                    }
                    Err(e) => {
                        log_message(&format!("❌ Failed to force restart goahead: {}", e), is_prod);
                    }
                }
            }
            ServerCmd::ReduceKernelLoad => {
                server_cmd.store(ServerCmd::None as u8, Ordering::Relaxed);
                let mut zte_count = 0;
                let mut high_prio_count = 0;
                let mut cpu_hog_count = 0;
                
                if let Ok(entries) = fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        let file_name = entry.file_name();
                        let name_str = file_name.to_string_lossy();
                        
                        if name_str.chars().all(|c| c.is_ascii_digit()) {
                            let pid = match name_str.parse::<u32>() {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            
                            // 1. 处理 zte 进程 (nice=15)
                            let cmdline_path = format!("/proc/{}/cmdline", name_str);
                            if let Ok(cmdline_content) = fs::read_to_string(&cmdline_path) {
                                if cmdline_content.contains("goahead") {
                                    match ProcessPriority::set_nice(pid, 10) {
                                        Ok(_) => {
                                            log_message(&format!("Set gohead process (PID: {}) priority to nice=15", pid), is_prod);
                                            zte_count += 1;
                                        }
                                        Err(e) => {
                                            log_message(&format!("Failed to set goahead process (PID: {}) priority: {}", pid, e), is_prod);
                                        }
                                    }
                                    continue;
                                }
                                if cmdline_content.contains("zte") {
                                    match ProcessPriority::set_nice(pid, 5) {
                                        Ok(_) => {
                                            log_message(&format!("Set zte process (PID: {}) priority to nice=10", pid), is_prod);
                                            zte_count += 1;
                                        }
                                        Err(e) => {
                                            log_message(&format!("Failed to set zte process (PID: {}) priority: {}", pid, e), is_prod);
                                        }
                                    }
                                    continue;
                                }
                            }
                            
                            // 2. 获取进程名和当前 nice 值
                            let comm_path = format!("/proc/{}/comm", name_str);
                            let stat_path = format!("/proc/{}/stat", name_str);
                            
                            if let Ok(comm) = fs::read_to_string(&comm_path) {
                                let comm = comm.trim();
                                
                                // 2a. 处理 ksoftirqd 和 dwc_otg_thread (nice=-5)
                                if comm.contains("ksoftirqd") || comm.contains("dwc_otg_thread") {
                                    match ProcessPriority::set_nice(pid, -5) {
                                        Ok(_) => {
                                            log_message(&format!("Reduced {} (PID: {}) priority to nice=-10", comm, pid), is_prod);
                                            cpu_hog_count += 1;
                                        }
                                        Err(e) => {
                                            log_message(&format!("Failed to reduce {} (PID: {}) priority: {}", comm, pid, e), is_prod);
                                        }
                                    }
                                    continue;
                                }
                                
                                // 2b. 处理 nice=-20 的进程 (改为 nice=0)
                                if let Ok(stat_content) = fs::read_to_string(&stat_path) {
                                    // stat 格式: pid (comm) state ... priority nice ...
                                    // nice 是第 19 个字段
                                    let parts: Vec<&str> = stat_content.split_whitespace().collect();
                                    if parts.len() >= 19 {
                                        if let Ok(current_nice) = parts[18].parse::<i32>() {
                                            if current_nice == -20 {
                                                match ProcessPriority::set_nice(pid, 0) {
                                                    Ok(_) => {
                                                        log_message(&format!("Adjusted {} (PID: {}) priority from -20 to 0", comm, pid), is_prod);
                                                        high_prio_count += 1;
                                                    }
                                                    Err(e) => {
                                                        log_message(&format!("Failed to adjust {} (PID: {}) priority: {}", comm, pid, e), is_prod);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                log_message(&format!("Kernel load reduction complete: zte={}, high_prio_adjusted={}, cpu_hogs={}", 
                    zte_count, high_prio_count, cpu_hog_count), is_prod);
                send_udp_notification(&format!("KERNEL_LOAD_REDUCED: ZTE={} HIGH_PRIO={} CPU_HOGS={}", 
                    zte_count, high_prio_count, cpu_hog_count), target_ip.clone(), is_prod);
            }
            ServerCmd::EnableKmsgMonitor => {
                server_cmd.store(ServerCmd::None as u8, Ordering::Relaxed);
                kmsg_monitor.enable(is_prod);
                send_udp_notification("KMSG_MONITOR_ENABLED", target_ip.clone(), is_prod);
            }
            ServerCmd::DisableKmsgMonitor => {
                server_cmd.store(ServerCmd::None as u8, Ordering::Relaxed);
                kmsg_monitor.disable(is_prod);
                send_udp_notification("KMSG_MONITOR_DISABLED", target_ip.clone(), is_prod);
            }
            ServerCmd::None => {}
        }
        
        if now.duration_since(last_snat_check) >= Duration::from_secs(SNAT_CHECK_INTERVAL) {
            let br_network = get_br_network(is_prod);
            let wan1_ip = get_wan_ip_address(is_prod);
    
            if !br_network.is_empty() && !wan1_ip.is_empty() {
                // 检查当前第一条规则是否包含正确的 WAN IP
                let check_cmd = "iptables -t nat -L POSTROUTING 1";
                let needs_update = match Command::new("sh").arg("-c").arg(check_cmd).output() {
                    Ok(output) => {
                        if output.status.success() {
                            let current_rule = String::from_utf8_lossy(&output.stdout);
                            // 检查规则是否包含正确的 WAN IP
                            let expected_pattern = format!("to:{}", wan1_ip);
                            !current_rule.contains(&expected_pattern)
                        } else {
                            // 如果获取规则失败，假定需要更新
                            true
                        }
                    }
                    Err(_) => {
                        // 如果执行命令失败，假定需要更新
                        true
                    }
                };

                if needs_update {
                    let ipt_cmds = [
                        format!("iptables -t nat -I POSTROUTING -s {}/32 -o wan1 -j SNAT --to-source {}", target_sock_ip, wan1_ip),
                        "iptables -t nat -D POSTROUTING 2".to_string(),
                    ];
            
                    for cmd in &ipt_cmds {
                        if let Err(e) = Command::new("sh").arg("-c").arg(cmd).status() {
                            if !is_prod {
                                log_message(&format!("Failed to adjust network parameter {}: {}", cmd, e), is_prod);
                            }
                        }
                    }
            
                    if !is_prod {
                        log_message(&format!("SNAT rule updated with new WAN IP: {}", wan1_ip), is_prod);
                    }
                } 
            }
            last_snat_check = now;
        }
        
        // 网络连通性检查 - 根据负载模式调整间隔
        if now.duration_since(last_network_check) >= Duration::from_secs(PING_INTERVAL) {
            match check_connectivity(&target_ip, is_prod) {
                (true, Some(connect_duration)) => {
                    if connect_duration.as_millis() > HIGH_LATENCY_THRESHOLD {
                        high_latency_count += 1;
                        log_message(&format!("High latency detected: {}ms (> {}ms)", connect_duration.as_millis(), HIGH_LATENCY_THRESHOLD), is_prod);
                        log_message(&format!("High latency count: {}/{}", high_latency_count, MAX_HIGH_LATENCY), is_prod);

                        send_udp_notification(&format!("HIGH_LATENCY: LATENCY={:.1}", connect_duration.as_millis()), target_ip.clone(), is_prod);
                        if connect_duration.as_millis() > HIGH_LATENCY_THRESHOLD_MAX && high_latency_count < MAX_HIGH_LATENCY {
                            high_latency_count = MAX_HIGH_LATENCY
                        }
                
                        if high_latency_count == MAX_HIGH_LATENCY {
                            log_message(&format!("WARN: {} consecutive high latency connections detected", MAX_HIGH_LATENCY), is_prod);
                            force_kill_process(is_prod, "adbd");
                            force_kill_process(is_prod, "goahead");
                            throttle_network_parameters(is_prod);
                        }
                    } else {
                        if high_latency_count >= MAX_HIGH_LATENCY {
                            if connect_duration.as_millis() < HIGH_LATENCY_THRESHOLD_MIN  {
                                restore_network_parameters(is_prod);
                                force_start_goahead_process(is_prod);
                                clear_page_cache(is_prod);
                                high_latency_count = 1
                            } else {
                                high_latency_count = MAX_HIGH_LATENCY
                            }
                        } else {
                            high_latency_count = high_latency_count.saturating_sub(1);
                        }
                        send_udp_notification(&format!("NORMAL_LATENCY: LATENCY={:.1}", connect_duration.as_millis()), target_ip.clone(), is_prod);
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
                    if failure_count == WARN_FAILURES {
                        log_message(&format!("Critical: {} consecutive pre failure detected", WARN_FAILURES), is_prod);
                        log_message("try reset android usb...", is_prod);
                        reset_android_usb(is_prod);
                    } else if failure_count == MAX_FAILURES {
                        log_message(&format!("Critical: {} consecutive failures detected", MAX_FAILURES), is_prod);
                        log_message("Initiating system reboot...", is_prod);
                        reboot_system(is_prod);
                    }
                }
            }
            last_network_check = now;
        }

        // KMSG 监控检查（在主循环中处理，无线程开销）
        kmsg_monitor.check(&target_ip, is_prod);

        // 睡眠1秒后继续检查，避免忙等待
        thread::sleep(Duration::from_millis(500));
    }
}

pub struct ProcessPriority;
impl ProcessPriority {
    /// 设置进程的 nice 值
    /// priority: -20 (最高) 到 19 (最低)
    pub fn set_nice(pid: u32, priority: i32) -> Result<(), String> {
        unsafe {
            // 0 表示当前进程，>0 表示具体 PID
            let who: libc::c_uint = pid;
            let ret = libc::setpriority(libc::PRIO_PROCESS as libc::c_int, who, priority);
            if ret == -1 {
                let err = io::Error::last_os_error();
                return Err(format!(
                    "setpriority({}) for PID {} failed: {}",
                    priority, pid, err
                ));
            }
            Ok(())
        }
    }
    
    /// 设置当前进程的 nice 值
    pub fn set_current_nice(priority: i32) -> Result<(), String> {
        Self::set_nice(0, priority)
    }
}

fn reset_android_usb(is_prod: bool) {
    let commands = [
        "echo 0 > /sys/class/android_usb/android0/enable",
        "echo 1 > /sys/class/android_usb/android0/enable",
    ];
    for cmd in commands.iter() {
        if let Err(e) = Command::new("sh").arg("-c").arg(cmd).status() {
            if !is_prod {
                log_message(&format!("Failed to adjust network parameter {}: {}", cmd, e), is_prod);
            }
        }
        thread::sleep(Duration::from_millis(3000));
    }
}

fn throttle_network_parameters(is_prod: bool) {
    // 调整TCP参数来减轻网络栈负担
    let commands = [
        "echo 3500 > /proc/sys/net/nf_conntrack_max",
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
        "echo 4096 > /proc/sys/net/nf_conntrack_max",
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
fn get_wan_ip_address(is_prod: bool) -> String {
    // 方法1: 使用 ip 命令获取 wan1 接口的 IP
    if let Ok(output) = Command::new("ip")
        .args(["addr", "show", "wan1"])
        .output() 
    {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.trim().starts_with("inet ") {
                    let parts: Vec<&str> = line.trim().split_whitespace().collect();
                    if parts.len() >= 2 {
                        let ip_with_mask = parts[1];
                        if let Some(ip) = ip_with_mask.split('/').next() {
                            if !ip.is_empty() && ip != "127.0.0.1" {
                                // log_message(&format!("Found wan1 IP via ip command: {}", ip), is_prod);
                                return ip.to_string();
                            }
                        }
                    }
                }
            }
        }
    }

    log_message("Could not determine wan1 IP address", is_prod);
    String::new()
}

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
                        // log_message(&format!("Found br0 network: {}", network), is_prod);
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

fn optimize_network_parameters(is_prod: bool, addr: String) {
    // 调整TCP参数来减轻网络栈负担
    let ip_only = match addr.parse::<SocketAddr>() {
        Ok(sock) => sock.ip().to_string(),
        Err(_)   => {
            log_message(&format!("invalid addr: {}", addr), is_prod);
            return;
        }
    };
    let br_network = get_br_network(is_prod);
    let wan1_ip = get_wan_ip_address(is_prod);

    let commands = [
        "echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
        "echo 2200 > /sys/module/net_ext_modul/parameters/skb_num_limit",
        "echo 1400 > /sys/module/net_ext_modul/parameters/skb_max_panic",
        "echo 1000 > /proc/sys/net/core/netdev_max_backlog",
        "echo 5000 > /proc/sys/net/unix/max_dgram_qlen",
        "echo 128 > /proc/sys/net/ipv4/tcp_max_syn_backlog",

        "echo 5 > /proc/sys/net/ipv4/tcp_retries2",
        "echo 15 > /proc/sys/net/ipv4/tcp_fin_timeout",
        "echo 300 > /proc/sys/net/ipv4/tcp_keepalive_time",

        "echo 10 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_time_wait",
        "echo 300 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established",
        "echo 10 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_syn_sent2",
        "echo 20 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_close",

        "echo 10 > /proc/sys/net/ipv4/netfilter/ip_conntrack_udp_timeout",
        "echo 10 > /proc/sys/net/ipv4/netfilter/ip_conntrack_udp_timeout_stream",
        "echo 4096 > /proc/sys/net/nf_conntrack_max",
        "echo 450 > /proc/sys/net/netfilter/nf_conntrack_expect_max",
        
        // "echo 0 > /proc/sys/net/netfilter/nf_conntrack_log_invalid",
        // "echo 0 > /proc/sys/net/netfilter/nf_conntrack_checksum",
        "echo 1 > /proc/sys/net/netfilter/nf_conntrack_tcp_loose",

        "echo 600 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established",
        "echo 10 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent",
        "echo 10 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_recv",

        "echo 30 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_fin_wait",
        "echo 30 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_last_ack",
        "echo 10 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close",
        "echo 30 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait",

        "echo 30 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait",
        "echo 3 > /proc/sys/net/netfilter/nf_conntrack_tcp_max_retrans",
        "echo 30 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_max_retrans",
        "echo 10 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout",
        "echo 60 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream",
        "echo 10 > /proc/sys/net/netfilter/nf_conntrack_icmp_timeout",

        "echo 100 > /proc/sys/net/netfilter/nf_conntrack_generic_timeout",
        //"echo 0 > /proc/sys/net/ipv4/tcp_window_scaling"
        // "echo 1 > /proc/net/fastnat_level"

        // ========== IP分片重组优化 ==========
        "echo 131072 > /proc/sys/net/ipv4/ipfrag_low_thresh",
        "echo 196608 > /proc/sys/net/ipv4/ipfrag_high_thresh",
        "echo 20 > /proc/sys/net/ipv4/ipfrag_time",

        // ========== TCP内存极致压缩 ==========
        "echo 256 512 768 > /proc/sys/net/ipv4/tcp_mem",
        "echo 4096 8192 32768 > /proc/sys/net/ipv4/tcp_rmem",
        "echo 4096 8192 32768 > /proc/sys/net/ipv4/tcp_wmem",
        "echo 64 > /proc/sys/net/ipv4/tcp_max_orphans",
        "echo 128 > /proc/sys/net/ipv4/tcp_max_tw_buckets",

        // ========== TCP保活与重传 ==========
        "echo 3 > /proc/sys/net/ipv4/tcp_keepalive_probes",
        "echo 5 > /proc/sys/net/ipv4/tcp_syn_retries",
        "echo 5 > /proc/sys/net/ipv4/tcp_synack_retries",
        "echo 0 > /proc/sys/net/ipv4/tcp_slow_start_after_idle",

        // ========== 路由表精简 ==========
        "echo 4096 > /proc/sys/net/ipv4/route/max_size",
        "echo 256 > /proc/sys/net/ipv4/route/gc_thresh",
        "echo 60 > /proc/sys/net/ipv4/route/gc_timeout",

        // ========== ARP/邻居表压缩 ==========
        "echo 256 > /proc/sys/net/ipv4/neigh/default/gc_thresh1",
        "echo 512 > /proc/sys/net/ipv4/neigh/default/gc_thresh2",
        "echo 2048 > /proc/sys/net/ipv4/neigh/default/gc_thresh3",
        "echo 15 > /proc/sys/net/ipv4/neigh/default/base_reachable_time",

        // ========== UDP内存压缩 ==========
        "echo 256 512 768 > /proc/sys/net/ipv4/udp_mem",
        "echo 2048 > /proc/sys/net/ipv4/udp_rmem_min",
        "echo 2048 > /proc/sys/net/ipv4/udp_wmem_min",

        // ========== 杂项精简 ==========
        "echo 5 > /proc/sys/net/ipv4/igmp_max_memberships",
        "echo 8192 > /proc/sys/net/ipv4/inet_peer_threshold",
        "echo 300 > /proc/sys/net/ipv4/inet_peer_maxttl",

        // ========== ICMP限速 ==========
        "echo 100 > /proc/sys/net/ipv4/icmp_ratelimit",
        "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",

        // ========== Kernel核心参数 ==========
        "echo 0 > /proc/sys/kernel/randomize_va_space",
        "echo 0 > /proc/sys/kernel/panic_on_oops",
        "echo '|/bin/false' > /proc/sys/kernel/core_pattern",
        "echo 0 > /proc/sys/kernel/core_uses_pid",
        "echo 1 1 1 1 > /proc/sys/kernel/printk",
        "echo 0 > /proc/sys/kernel/sysrq",
        "echo 256 > /proc/sys/kernel/threads-max",
        "echo 4096 > /proc/sys/kernel/msgmnb",
        "echo 96 > /proc/sys/kernel/msgmni",

        // ========== VM内存管理 ==========
        "echo 0 > /proc/sys/vm/panic_on_oom",
        "echo 2048 > /proc/sys/vm/min_free_kbytes",

        // ========== 实时内核优化 ==========
        "echo 200000 > /proc/sys/kernel/sched_rt_period_us",

        "echo 8192 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit_max",
        "echo 4096 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit",
        "echo 1024 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit_min",
        "echo 200 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/hold_time"
    ];

    if !br_network.is_empty() && !wan1_ip.is_empty() {
        let ipt_cmds = [
            "iptables -P INPUT ACCEPT".to_string(),
            "iptables -P FORWARD ACCEPT".to_string(),
            "iptables -P OUTPUT ACCEPT".to_string(),
            "iptables -F -t filter".to_string(),
            "iptables -F -t nat".to_string(),
            // "iptables -t nat -A POSTROUTING -s 192.168.8.2/32 -o wan1 -j MASQUERADE",
            // format!("iptables -t nat -A POSTROUTING -s {}/32 -o wan1 -j MASQUERADE", ip_only),
            format!("iptables -t nat -I POSTROUTING -s {}/32 -o wan1 -j SNAT --to-source {}", ip_only, wan1_ip),
            //&format!("iptables -t nat -A POSTROUTING -s {} -o wan1 -j MASQUERADE", br_network),
            "ip6tables -F".to_string(),
            "ifconfig wan1 txqueuelen 100".to_string(),
            "ifconfig br0 txqueuelen 500".to_string(),
            "ifconfig usblan0 txqueuelen 100".to_string(),
        ];
        for cmd in &ipt_cmds {
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

fn daemonize_simple(is_prod: bool) {
    let stdout = if is_prod { "/dev/null" } else { "/etc_rw/zxping.log" };

    let dev_null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        // .open(stdout)
        // .open("/dev/null")
        .open("/etc_rw/zxping.log")
        .expect(&format!("cannot open {}", stdout));

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
        Ok(stream) => {
            drop(stream);
            let duration = start.elapsed();
            if !is_prod {
                // log_message(&format!("TCP connect successful, took {:?}", duration.as_millis()), is_prod);
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
                        // log_message(&format!("UDP notification sent: {}", full_message), is_prod);
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
    let mut child = Command::new("/bin/adbd")
        .stdout(Stdio::null())  // 标准输出重定向到 /dev/null
        .stderr(Stdio::null())  // 标准错误重定向到 /dev/null
        .spawn()
        .map_err(|e| format!("Failed to start adbd: {}", e))?;
    
    // 4. 设置子进程优先级
    let pid = child.id();
    log_message(&format!("set adbd pid={} pri", pid), is_prod);
    if let Err(e) = ProcessPriority::set_nice(pid, 15) {
        log_message(&format!("Warning: Could not set priority for adbd: {}", e), is_prod);
    } else {
        log_message(&format!("Set adbd (PID: {}) priority to nice={}", pid, 15), is_prod);
    }
    
    log_message("adbd force restarted successfully", is_prod);
    re_enable_adb_function(is_prod);
    Ok(())
}

pub fn force_start_goahead_process(is_prod: bool) -> Result<(), String> {
        log_message("Force restart goahead process...", is_prod);
        
        // 启动进程
        let mut child = Command::new("/bin/goahead")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to start goahead: {}", e))?;
        
        // 设置子进程优先级
        let pid = child.id();

        log_message(&format!("set goahead pid={} pri", pid), is_prod);
        if let Err(e) = ProcessPriority::set_nice(pid, 15) {
            log_message(&format!("Warning: Could not set priority for goahead: {}", e), is_prod);
        } else {
            log_message(&format!("Set goahead (PID: {}) priority to nice={}", pid, 15), is_prod);
        }
        // 分离子进程，让它在后台运行
        // 如果你不需要等待进程结束，可以注释掉下面的 wait
        // let _ = child.wait(); // 不关心退出状态
        log_message("goahead force restarted successfully", is_prod);
        Ok(())
}


// 强制重启adbd进程
fn force_kill_process(is_prod: bool, process_name: &str) -> Result<(), String> {
    log_message("Force restarting process...", is_prod);
    
     // 1. 查找并杀死所有adbd进程
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            
            if name_str.chars().all(|c| c.is_ascii_digit()) {
                let cmdline_path = format!("/proc/{}/cmdline", name_str);
                if let Ok(cmdline_content) = fs::read_to_string(&cmdline_path) {
                    if cmdline_content.contains(process_name) {
                        // 修复：将 Cow<'_, str> 转换为 String
                        let pid = name_str.to_string();
                        // 杀死adbd进程
                        let _ = Command::new("kill")
                            .arg("-9")
                            .arg(&pid)
                            .status();
                        log_message(&format!("force Killed process (PID: {})", pid), is_prod);
                    }
                }
            }
        }
    }
    
    // 2. 等待一段时间确保进程完全终止
    thread::sleep(Duration::from_secs(1));

    return Ok(())
}

// 禁用 ADB 功能（通过修改 USB 配置）
fn disable_adb_function(is_prod: bool) -> Result<(), String> {
    log_message("Disabling ADB function via USB configuration...", is_prod);
    
    let commands = [
        "echo 0 > /sys/class/android_usb/android0/enable",
        "echo ecm > /sys/class/android_usb/android0/functions",
        "echo 1 > /sys/class/android_usb/android0/enable",
        "echo 8192 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit_max",
        "echo 4096 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit",
        "echo 1024 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit_min",
        "echo 200 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/hold_time"
    ];
    
    for cmd in commands.iter() {
        match Command::new("sh").arg("-c").arg(cmd).status() {
            Ok(status) => {
                if !status.success() {
                    log_message(&format!("Warning: command may have failed: {}", cmd), is_prod);
                }
            }
            Err(e) => {
                return Err(format!("Failed to execute '{}': {}", cmd, e));
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    
    log_message("ADB function disabled, USB now in ECM mode only", is_prod);
    Ok(())
}

fn re_enable_adb_function(is_prod: bool) -> Result<(), String> {
    log_message("Disabling ADB function via USB configuration...", is_prod);
    
    let commands = [
        "echo 0 > /sys/class/android_usb/android0/enable",
        "echo ecm,adb > /sys/class/android_usb/android0/functions",
        "echo 1 > /sys/class/android_usb/android0/enable",
        "echo 8192 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit_max",
        "echo 4096 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit",
        "echo 1024 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit_min",
        "echo 200 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/hold_time"
    ];
    
    for cmd in commands.iter() {
        match Command::new("sh").arg("-c").arg(cmd).status() {
            Ok(status) => {
                if !status.success() {
                    log_message(&format!("Warning: command may have failed: {}", cmd), is_prod);
                }
            }
            Err(e) => {
                return Err(format!("Failed to execute '{}': {}", cmd, e));
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    
    log_message("ADB function disabled, USB now in ECM mode only", is_prod);
    Ok(())
}