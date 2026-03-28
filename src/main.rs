use radvd_core::socket::open_icmpv6_socket;
use std::env;
use std::fs::{self};
use std::io::{self, Read, Write};
use std::net::UdpSocket;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::UNIX_EPOCH;
use std::time::{Duration, Instant, SystemTime};

use libc;

use daemonize::Daemonize;
mod radvd; // 声明模块

const DEFAULT_TARGET_IP: &str = "127.0.0.1:80";
const PING_INTERVAL: u64 = 60; // 网络检查间隔60秒
const SNAT_CHECK_INTERVAL: u64 = 300;
const DNS_CONFIG_CHECK_INTERVAL: u64 = 300; // DNS配置检查间隔120秒
const RADVD_PREFIX_CHECK_INTERVAL: u64 = 120;
const SNTP_SYNC_INTERVAL: u64 = 3600; // SNTP同步间隔1小时
const SNTP_TIMEOUT: Duration = Duration::from_secs(5); // SNTP超时时间
const SNTP_SERVERS: &[&str] = &[
    // 域名作为后备（当DNS可用时）
    "ntp.aliyun.com:123",
    "time.windows.com:123",
    "cn.pool.ntp.org:123",
]; // SNTP服务器列表（IP优先，避免DNS依赖）

const MEMORY_LOW_THRESHOLD_KB: u64 = 2000; // 内存临界阈值2MB（小于此值杀进程）
const MEMORY_CRITICAL_THRESHOLD_KB: u64 = 1600; // 内存临界阈值1600KB（小于此值杀进程）

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
const ENABLE_MEMORY_MONITOR: &[u8] = b"ENABLE_MEMORY_MONITOR";
const DISABLE_MEMORY_MONITOR: &[u8] = b"DISABLE_MEMORY_MONITOR";
const KILL_SIGNAL_RADVD: &[u8] = b"KILL_RADVD";
const KILL_SIGNAL_GOAHEAD: &[u8] = b"KILL_GOAHEAD";
const ADJUST_ZRAM: &[u8] = b"ADJUST_ZRAM";
const USB_FUNCTIONS: &[u8] = b"USB_FUNCTIONS";
const WAN_IP_ADDR: &[u8] = b"WAN_IP_ADDR";

// 内存监控配置
const MEMORY_MONITOR_INTERVAL: Duration = Duration::from_secs(6); // 内存检查间隔10秒

// echo -n "REDUCE_KERNEL_LOAD" | nc <TARGETIP> 1300

// 处理信号命令，直接在接收处执行对应操作
fn handle_restart_adb(target_ip: &str, is_prod: bool) {
    match force_restart_adbd_process(is_prod) {
        Ok(_) => {
            log_message("adbd force restarted successfully", is_prod);
            send_udp_notification("ADBD_FORCE_RESTARTED", target_ip.to_string(), is_prod);
        }
        Err(e) => {
            log_message(&format!("❌ Failed to force restart adbd: {}", e), is_prod);
        }
    }
}

fn handle_kill_adb(target_ip: &str, is_prod: bool) {
    match force_kill_process(is_prod, "adbd") {
        Ok(_) => {
            log_message("adbd killed successfully", is_prod);
            send_udp_notification("ADBD_FORCE_KILLED", target_ip.to_string(), is_prod);
        }
        Err(e) => {
            log_message(&format!("❌ Failed to kill adbd: {}", e), is_prod);
        }
    }
}

fn handle_restart_server(is_prod: bool) {
    reboot_system(is_prod);
}

fn handle_disable_adb(target_ip: &str, is_prod: bool) {
    match disable_adb_function(is_prod) {
        Ok(_) => {
            log_message("adb function disabled successfully", is_prod);
            send_udp_notification("ADB_FUNCTION_DISABLED", target_ip.to_string(), is_prod);
        }
        Err(e) => {
            log_message(
                &format!("❌ Failed to disable adb function: {}", e),
                is_prod,
            );
        }
    }
}

fn handle_restart_goahead(target_ip: &str, is_prod: bool) {
    match force_start_goahead_process(is_prod) {
        Ok(_) => {
            log_message("goahead force restarted successfully", is_prod);
            send_udp_notification("GOAHEAD_FORCE_RESTARTED", target_ip.to_string(), is_prod);
        }
        Err(e) => {
            log_message(
                &format!("❌ Failed to force restart goahead: {}", e),
                is_prod,
            );
        }
    }
}

fn handle_reduce_kernel_load(target_ip: &str, is_prod: bool) {
    let mut zte_count = 0;
    let high_prio_count = 0;
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

                // 1. 处理 goahead 和 zte 进程
                let cmdline_path = format!("/proc/{}/cmdline", name_str);
                if let Ok(cmdline_content) = fs::read_to_string(&cmdline_path) {
                    if cmdline_content.contains("goahead") {
                        match ProcessPriority::set_nice(pid, 10) {
                            Ok(_) => {
                                log_message(
                                    &format!(
                                        "Set goahead process (PID: {}) priority to nice=10",
                                        pid
                                    ),
                                    is_prod,
                                );
                                zte_count += 1;
                            }
                            Err(e) => {
                                log_message(
                                    &format!(
                                        "Failed to set goahead process (PID: {}) priority: {}",
                                        pid, e
                                    ),
                                    is_prod,
                                );
                            }
                        }
                        continue;
                    }
                    if cmdline_content.contains("zte") {
                        match ProcessPriority::set_nice(pid, 5) {
                            Ok(_) => {
                                log_message(
                                    &format!("Set zte process (PID: {}) priority to nice=5", pid),
                                    is_prod,
                                );
                                zte_count += 1;
                            }
                            Err(e) => {
                                log_message(
                                    &format!(
                                        "Failed to set zte process (PID: {}) priority: {}",
                                        pid, e
                                    ),
                                    is_prod,
                                );
                            }
                        }
                        continue;
                    }
                }

                // 2. 处理 apmStaloss_wq 和 dw-mci-card 进程
                let comm_path = format!("/proc/{}/comm", name_str);
                if let Ok(comm) = fs::read_to_string(&comm_path) {
                    let comm = comm.trim();
                    if comm.contains("apmStaloss_wq") || comm.contains("dw-mci-card") {
                        match ProcessPriority::set_nice(pid, 10) {
                            Ok(_) => {
                                log_message(
                                    &format!("Reduced {} (PID: {}) priority to nice=10", comm, pid),
                                    is_prod,
                                );
                                cpu_hog_count += 1;
                            }
                            Err(e) => {
                                log_message(
                                    &format!(
                                        "Failed to reduce {} (PID: {}) priority: {}",
                                        comm, pid, e
                                    ),
                                    is_prod,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    log_message(
        &format!(
            "Kernel load reduction complete: zte={}, high_prio_adjusted={}, cpu_hogs={}",
            zte_count, high_prio_count, cpu_hog_count
        ),
        is_prod,
    );
    send_udp_notification(
        &format!(
            "KERNEL_LOAD_REDUCED: ZTE={} HIGH_PRIO={} CPU_HOGS={}",
            zte_count, high_prio_count, cpu_hog_count
        ),
        target_ip.to_string(),
        is_prod,
    );
}

fn handle_kill_goahead(target_ip: &str, is_prod: bool) {
    match force_kill_process(is_prod, "goahead") {
        Ok(_) => {
            log_message("goahead killed successfully", is_prod);
            send_udp_notification("GOAHEAD_KILLED", target_ip.to_string(), is_prod);
        }
        Err(e) => {
            log_message(&format!("❌ Failed to kill goahead: {}", e), is_prod);
        }
    }
}

fn handle_kill_radvd(target_ip: &str, is_prod: bool) {
    let _ = force_kill_process(is_prod, "dhcp6s");
    match force_kill_process(is_prod, "radvd") {
        Ok(_) => {
            log_message("radvd killed successfully", is_prod);
            send_udp_notification("RADVD_KILLED", target_ip.to_string(), is_prod);
        }
        Err(e) => {
            log_message(&format!("❌ Failed to kill radvd: {}", e), is_prod);
        }
    }
}

fn handle_adjust_zram(target_ip: &str, is_prod: bool) {
    log_message("Adjusting zram configuration...", is_prod);

    let commands = [
        "swapoff /dev/zram0",
        "echo 1 > /sys/block/zram0/reset",
        "echo 3 > /proc/sys/vm/drop_caches",
        "echo 4194304 > /sys/block/zram0/disksize",
        "mkswap /dev/zram0",
        "swapon -p 100 /dev/zram0",
        "echo 5 > /proc/sys/vm/swappiness",
        "echo 50 > /proc/sys/vm/vfs_cache_pressure",
        "echo 1 > /proc/sys/vm/overcommit_memory",
    ];

    for cmd in commands.iter() {
        match Command::new("sh").arg("-c").arg(cmd).status() {
            Ok(status) => {
                if !status.success() {
                    log_message(
                        &format!("Warning: command may have failed: {}", cmd),
                        is_prod,
                    );
                }
            }
            Err(e) => {
                log_message(&format!("Failed to execute '{}': {}", cmd, e), is_prod);
            }
        }
    }

    log_message("ZRAM configuration adjusted successfully", is_prod);
    send_udp_notification("ZRAM_ADJUSTED", target_ip.to_string(), is_prod);
}

/// 内存监控状态 - 极简设计，无线程
struct MemoryMonitor {
    enabled: AtomicBool,
    last_check_time: Option<Instant>,
}

impl MemoryMonitor {
    fn new() -> Self {
        MemoryMonitor {
            enabled: AtomicBool::new(false),
            last_check_time: None,
        }
    }

    fn enable(&mut self, is_prod: bool) {
        if !self.enabled.load(Ordering::Relaxed) {
            self.enabled.store(true, Ordering::Relaxed);
            log_message("Memory monitor enabled", is_prod);
        }
    }

    fn disable(&mut self, is_prod: bool) {
        if self.enabled.load(Ordering::Relaxed) {
            self.enabled.store(false, Ordering::Relaxed);
            log_message("Memory monitor disabled", is_prod);
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// 在主循环中调用，检查内存
    fn check(&mut self, is_prod: bool, target_ip: &str) {
        if !self.is_enabled() {
            return;
        }

        // 检查间隔控制
        let now = Instant::now();
        if let Some(last_check) = self.last_check_time {
            if now.duration_since(last_check) < MEMORY_MONITOR_INTERVAL {
                return;
            }
        }
        self.last_check_time = Some(now);

        if let Some(free_kb) = get_free_memory_kb() {
            if free_kb < MEMORY_LOW_THRESHOLD_KB {
                log_message(
                    &format!(
                        "CRITICAL: Free memory {}KB is below threshold {}KB! Killing adbd and goahead...",
                        free_kb, MEMORY_LOW_THRESHOLD_KB
                    ),
                    is_prod,
                );

                let _ = force_kill_process(is_prod, "dnsmasq");
                let _ = force_kill_process(is_prod, "dhcp6s");
                let _ = force_kill_process(is_prod, "radvd");
                let _ = force_kill_process(is_prod, "adbd");
                let _ = std::fs::write("/proc/sys/vm/compact_memory", b"1\n");

                if free_kb < MEMORY_CRITICAL_THRESHOLD_KB {
                    let _ = force_kill_process(is_prod, "goahead");
                    // 额外清理 page cache
                    let _ = std::fs::write("/proc/sys/vm/drop_caches", b"1\n");
                    thread::sleep(Duration::from_secs(10));
                }
            }
        } else {
            log_message("Failed to get memory info via sysinfo", is_prod);
        }
    }
}

// use signal_hook::{
//     consts::SIGTERM,
//     iterator::{exfiltrator::WithOrigin, SignalsInfo},  // 引入 WithOrigin
// };
// use std::sync::Arc;

// fn set_process_name(name: &str) {
//     // 设置 /proc/[pid]/comm 显示的短名称 (用于 top, htop)
//     let c_name = std::ffi::CString::new(name).unwrap();
//     unsafe {
//         libc::prctl(libc::PR_SET_NAME, c_name.as_ptr(), 0, 0, 0);
//     }
//     // 设置 ps -ef 显示的完整命令行 (argv[0])
//     proctitle::set_title(name);
// }

/// 热插拔事件日志路径
// const HOTPLUG_LOG_PATH: &str = "/etc_rw/hotplug.log";

/// 检测并处理热插拔事件
/// 当程序被注册为 /proc/sys/kernel/hotplug 处理器时，内核会通过环境变量传递事件
fn handle_hotplug_event() -> bool {
    // 检查热插拔相关的环境变量
    let action = env::var("ACTION").ok();
    let devpath = env::var("DEVPATH").ok();
    let subsystem = env::var("SUBSYSTEM").ok();
    // let seqnum = env::var("SEQNUM").ok();

    // 如果没有热插拔环境变量，说明是正常启动
    if action.is_none() && devpath.is_none() && subsystem.is_none() {
        return false;
    }

    // 构建日志内容
    // let timestamp = SystemTime::now()
    //     .duration_since(UNIX_EPOCH)
    //     .unwrap_or_default()
    //     .as_secs();
    
    // let log_entry = format!(
    //     "[{}] ACTION={} DEVPATH={} SUBSYSTEM={} SEQNUM={}\n",
    //     timestamp,
    //     action.as_deref().unwrap_or("-"),
    //     devpath.as_deref().unwrap_or("-"),
    //     subsystem.as_deref().unwrap_or("-"),
    //     seqnum.as_deref().unwrap_or("-")
    // );

    // let _ = fs::OpenOptions::new()
    //     .create(true)
    //     .append(true)
    //     .open(HOTPLUG_LOG_PATH)
    //     .and_then(|mut f| f.write_all(log_entry.as_bytes()));

    // 处理 usblan0 上线事件
    let action_str = action.as_deref().unwrap_or("");
    let devpath_str = devpath.as_deref().unwrap_or("");
    let subsystem_str = subsystem.as_deref().unwrap_or("");
    
    if action_str == "online" && devpath_str.contains("usblan0") && subsystem_str == "net" {
        // 检查是否为桥接模式
        let lan_enable = Command::new("nv")
            .args(["get", "LanEnable"])
            .output()
            .ok()
            .and_then(|o| if o.status.success() { Some(String::from_utf8_lossy(&o.stdout).trim().to_string()) } else { None })
            .unwrap_or_default();
        
        let need_jilian = Command::new("nv")
            .args(["get", "need_jilian"])
            .output()
            .ok()
            .and_then(|o| if o.status.success() { Some(String::from_utf8_lossy(&o.stdout).trim().to_string()) } else { None })
            .unwrap_or_default();
        
        if lan_enable == "0" && need_jilian == "0" {
            // 检查 usblan0 是否在 br0 网桥中
            let in_bridge = match Command::new("brctl").args(["show"]).output() {
                Ok(output) => {
                    if output.status.success() {
                        String::from_utf8_lossy(&output.stdout)
                            .lines()
                            .any(|line| line.contains("usblan0"))
                    } else {
                        false
                    }
                }
                Err(_) => false,
            };
            
            if !in_bridge {
                // let _ = fs::OpenOptions::new()
                //     .create(true)
                //     .append(true)
                //     .open(HOTPLUG_LOG_PATH)
                //     .and_then(|mut f| f.write_all(b"[hotplug] usblan0 not in br0, re-adding...\n"));
                
                // 重新加入网桥
                let _ = Command::new("brctl").args(["addif", "br0", "usblan0"]).status();
                // thread::sleep(Duration::from_millis(1000));
                let _ = Command::new("ip").args(["link", "set", "usblan0", "up"]).status();
                let _ = Command::new("ifconfig").args(["br0", "up"]).status();
                let _ = Command::new("ifconfig").args(["usblan0", "up"]).status();
                
                // let _ = fs::OpenOptions::new()
                //     .create(true)
                //     .append(true)
                //     .open(HOTPLUG_LOG_PATH)
                //     .and_then(|mut f| f.write_all(b"[hotplug] usblan0 re-added to br0 done\n"));
            }
        }
    }

    true
}

fn main() {
    // 首先检查是否为热插拔事件调用
    if handle_hotplug_event() {
        return;
    }

    // 设置进程名
    // set_process_name("ztedm_timer");

    let args: Vec<String> = env::args().collect();

    // 检查是否需要后台运行
    let mut is_prod = false;
    if args.iter().any(|arg| arg == "--isprod") {
        is_prod = true;
    }

    if args.iter().any(|arg| arg == "--background" || arg == "-b") {
        daemonize_simple(is_prod);
    }

    // let running = Arc::new(AtomicBool::new(true));
    // let r = running.clone();

    // let mut signals = SignalsInfo::<WithOrigin>::new(&[SIGTERM]).unwrap();

    // thread::spawn(move || {
    //     for info in signals.forever() {
    //         // 现在可以获取发送者 PID
    //         match &info.process {
    //             Some(process) => {
    //                 let pid = process.pid;
    //                 // 尝试读取发送者命令名
    //                 let cmd = fs::read_to_string(format!("/proc/{}/comm", pid))
    //                     .map(|s| s.trim().to_string())
    //                     .unwrap_or_else(|_| "unknown".to_string());

    //                 eprintln!("Received SIGTERM from PID {} ({})", pid, cmd);
    //             }
    //             None => eprintln!("Received SIGTERM from Kernel/System"),
    //         }

    //         r.store(false, Ordering::SeqCst);
    //         break;
    //     }
    // });
    // while running.load(Ordering::SeqCst) {
    //     // 你的主循环
    //     std::thread::sleep(std::time::Duration::from_secs(1));
    // }

    // eprintln!("Shutting down gracefully...");
    // return;

    let target_ip = get_target_ip();

    if !is_prod {
        println!("Network monitor started for {}", target_ip);
        println!("Network check interval: {} seconds", PING_INTERVAL);
        println!("Reboot after {} consecutive failures", MAX_FAILURES);
        println!("Usage: {} [TARGET_IP:PORT] [--background] [--isprod]", args[0]);
    }

    let target_sock_ip = match target_ip.parse::<SocketAddr>() {
        Ok(sock) => sock.ip().to_string(),
        Err(_) => {
            log_message(&format!("invalid target_ip:PORT: {}", target_ip), is_prod);
            return;
        }
    };
    log_message(
        &format!("Network monitor started for {}", target_ip),
        is_prod,
    );

    let wan1_ip_check = get_wan_ip_address(is_prod);
    if wan1_ip_check.is_empty() {
        return
    }

    // 创建内存监控器（极简设计，无线程）
    let mut memory_monitor = MemoryMonitor::new();

    // 启动信号监听（同时支持 IPv4 和 IPv6）
    let signal_listener = TcpListener::bind(("::", SIGNAL_LISTEN_PORT)).expect("bind signal port");
    // 设置 IPV6_V6ONLY 为 false，允许 IPv4 映射到 IPv6
    let socket_fd = signal_listener.as_raw_fd();
    unsafe {
        let opt: libc::c_int = 0;
        libc::setsockopt(
            socket_fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    signal_listener
        .set_nonblocking(true)
        .expect("set_nonblocking");

    let mut failure_count = 0;
    let mut high_latency_count = 0;
    let mut last_network_check = Instant::now();
    let mut last_snat_check = Instant::now();
    let mut current_snat_wan_ip = String::new();
    // let mut last_udp_notification = Instant::now();
    // let mut last_adbd_check = Instant::now();
    // let mut last_log_prune = Instant::now();
    let mut last_dns_config_check = Instant::now();
    // 初始化为很早以前的时间，确保第一次 loop 就执行 radvd prefix 检查
    let mut last_radvdprefix_check =
        Instant::now() - Duration::from_secs(RADVD_PREFIX_CHECK_INTERVAL + 1);
    // SNTP同步时间检查
    let mut last_sntp_check = Instant::now() - Duration::from_secs(SNTP_SYNC_INTERVAL + 1);

    thread::sleep(Duration::from_secs(30));
    optimize_network_parameters(is_prod, target_ip.clone());
    let _ = force_kill_process(is_prod, "dnsmasq");
    let _ = force_kill_process(is_prod, "dhcp6s");
    let _ = force_kill_process(is_prod, "radvd");

    let _ = Command::new("nv").args(["set", "default_wan_rel="]).status();
    let _ = Command::new("nv").args(["set", "default_wan6_rel="]).status();


    // 检查 /etc/resolv.conf，如果为空或最后一行是 nameserver 127.0.0.1，则追加 DNS
    match fs::read_to_string("/etc/resolv.conf") {
        Ok(content) => {
            let trimmed = content.trim();
            let last_line = trimmed.lines().last().unwrap_or("").trim();
            if trimmed.is_empty() || last_line == "nameserver 127.0.0.1" {
                log_message("Adding fallback DNS 223.5.5.5 to /etc/resolv.conf", is_prod);
                let _ = fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open("/etc/resolv.conf")
                    .and_then(|mut f| {
                        if !trimmed.is_empty() && !trimmed.ends_with('\n') {
                            f.write_all(b"\n")?;
                        }
                        f.write_all(b"nameserver 223.5.5.5\n")
                    });
            }
        }
        Err(_) => {
            // 文件不存在或无法读取，尝试创建
            let _ = fs::write("/etc/resolv.conf", b"nameserver 223.5.5.5\n");
        }
    }

    // 检测 nv get LanEnable 和 nv get need_jilian，如果都返回0则配置网桥
    let lan_enable = match Command::new("nv").arg("get").arg("LanEnable").output() {
        Ok(output) => {
            if output.status.success() {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    };
    let need_jilian = match Command::new("nv").arg("get").arg("need_jilian").output() {
        Ok(output) => {
            if output.status.success() {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    };
    let radvd_iface_name = "br0";

    if lan_enable == "0" && need_jilian == "0" {
        // 注册自己为热插拔处理器
        let _ = std::fs::write("/proc/sys/kernel/hotplug", b"/etc_rw/zxic_ping\n");

        log_message("LanEnable=0 and need_jilian=0, configuring bridge...", is_prod);
        let _ = Command::new("brctl").args(["addbr", "br0"]).status();
        let _ = Command::new("brctl").args(["stp", "br0", "off"]).status();
        let _ = Command::new("brctl").args(["addif", "br0", "usblan0"]).status();
        let _ = Command::new("ifconfig").args(["br0", "up"]).status();
        let _ = Command::new("ifconfig").args(["usblan0", "up"]).status();

        // 获取 IPv6 前缀并配置 br0
        let wan1_ipv6_prefix = match Command::new("nv").arg("get").arg("wan1_ipv6_prefix_info").output() {
            Ok(output) => {
                if output.status.success() {
                    String::from_utf8_lossy(&output.stdout).trim().to_string()
                } else {
                    String::new()
                }
            }
            Err(_) => String::new(),
        };
        if !wan1_ipv6_prefix.is_empty() {
            let ipv6_addr = format!("{}:2/64", wan1_ipv6_prefix);
            log_message(&format!("Adding IPv6 address {} to br0", ipv6_addr), is_prod);
            let _ = Command::new("ip").args(["addr", "add", &ipv6_addr, "dev", "br0"]).status();
        }

        // 根据 target_sock_ip 计算 br0 的 IP 地址（将最后一位改为1）
        if let Some(last_dot) = target_sock_ip.rfind('.') {
            let base_ip = &target_sock_ip[..last_dot + 1];
            let br0_ip = format!("{}1", base_ip);
            log_message(&format!("Adding IPv4 address {}/24 to br0", br0_ip), is_prod);
            let _ = Command::new("ip")
                .args(["addr", "add", &format!("{}/24", br0_ip), "dev", "br0"])
                .status();
        }
    }

    let mut recv_buf = vec![0u8; 200];

    let icmp_socket_option = match open_icmpv6_socket() {
        Ok(socket) => {
            Some(socket) // 保存 socket 供后续使用
        }
        Err(e) => {
            log_message(&format!("Failed to create ICMPv6 socket:  {}", e), is_prod);
            None
        }
    };
    let mut radvd_conf_option = None;
    let mut current_radvd_pfx = String::new();

    loop {
        let now = Instant::now();

        if now.duration_since(last_radvdprefix_check)
            >= Duration::from_secs(RADVD_PREFIX_CHECK_INTERVAL)
        {
            let new_pfx = radvd::get_radvd_prefix();
            if !new_pfx.is_empty() && new_pfx != current_radvd_pfx {
                // 前缀发生变化，执行更新
                log_message(&format!("radvd prefix changed: {} -> {}", current_radvd_pfx, new_pfx), is_prod);
                current_radvd_pfx = new_pfx.clone();

                match radvd_conf_option.as_mut() {
                    Some(radvd_conf) => {
                        // 更新现有配置
                        if let Err(e) = radvd::update_radvd_prefix(radvd_conf, &new_pfx) {
                            log_message(&format!("radvd pfx update failed: {:?}", e), is_prod);
                        }
                    }
                    None => {
                        // 创建新配置并初始化
                        let mut new_conf = radvd::create_radvd_config(&new_pfx, radvd_iface_name);
                        if let Some(icmp_socket) = &icmp_socket_option {
                            radvd::setup_radvd(&mut new_conf, icmp_socket);
                        }
                        radvd_conf_option = Some(new_conf);
                    }
                }

                // 同时更新 br0 的 IPv6 地址（复制569行的逻辑）
                let ipv6_addr = format!("{}2/64", new_pfx);
                log_message(&format!("Updating IPv6 address {} to br0", ipv6_addr), is_prod);
                let _ = Command::new("ip").args(["addr", "add", &ipv6_addr, "dev", "br0"]).status();
            }

            last_radvdprefix_check = now;
        }


        // 处理 radvd socket（使用迭代器避免嵌套if let）
        if let (Some(icmp_socket), Some(radvd_conf)) =
            (&icmp_socket_option, radvd_conf_option.as_mut())
        {
            radvd::process_radvd_socket(radvd_conf, icmp_socket, &mut recv_buf);
        }

        // 处理 TCP 连接
        match signal_listener.accept() {
            // Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            //     // 非阻塞，没有新连接
            // }
            Err(_e) => {
                // if !is_prod {
                //     log_message(&format!("❌ Signal listener error: {}", e), is_prod);
                // }
            }
            Ok((mut stream, addr)) => {
                let mut buf = [0u8; 64];
                match stream.read(&mut buf) {
                    Ok(size) if size > 0 => {
                        let received = &buf[..size];

                        if received == RESTART_SIGNAL_ADBD {
                            log_message(
                                &format!("Received restart signal from {}", addr),
                                is_prod,
                            );
                            handle_restart_adb(&target_ip, is_prod);
                            let _ = stream.write_all(b"OK");
                        } else if received == KILL_SIGNAL_ADBD {
                            log_message(&format!("Received kill signal from {}", addr), is_prod);
                            handle_kill_adb(&target_ip, is_prod);
                            let _ = stream.write_all(b"OK");
                        } else if received == DISABLE_ADB {
                            log_message(
                                &format!("Received disable adb signal from {}", addr),
                                is_prod,
                            );
                            handle_disable_adb(&target_ip, is_prod);
                            let _ = stream.write_all(b"OK");
                        } else if received == RESTART_SIGNAL_SERVER {
                            log_message(
                                &format!("Received reboot signal from {}", addr),
                                is_prod,
                            );
                            handle_restart_server(is_prod);
                            let _ = stream.write_all(b"OK");
                        } else if received == RESTART_SIGNAL_GOAHEAD {
                            log_message(
                                &format!("Received restart goahead signal from {}", addr),
                                is_prod,
                            );
                            handle_restart_goahead(&target_ip, is_prod);
                            let _ = stream.write_all(b"OK");
                        } else if received == REDUCE_KERNEL_LOAD {
                            log_message(
                                &format!("Received reduce kernel load signal from {}", addr),
                                is_prod,
                            );
                            handle_reduce_kernel_load(&target_ip, is_prod);
                            let _ = stream.write_all(b"OK");
                        } else if received == ENABLE_MEMORY_MONITOR {
                            log_message(
                                &format!("Received enable memory monitor signal from {}", addr),
                                is_prod,
                            );
                            memory_monitor.enable(is_prod);
                            send_udp_notification(
                                "MEMORY_MONITOR_ENABLED",
                                target_ip.clone(),
                                is_prod,
                            );
                            let _ = stream.write_all(b"OK");
                        } else if received == DISABLE_MEMORY_MONITOR {
                            log_message(
                                &format!("Received disable memory monitor signal from {}", addr),
                                is_prod,
                            );
                            memory_monitor.disable(is_prod);
                            send_udp_notification(
                                "MEMORY_MONITOR_DISABLED",
                                target_ip.clone(),
                                is_prod,
                            );
                            let _ = stream.write_all(b"OK");
                        } else if received == SIGNAL_PING {
                            let _ = stream.write_all(b"OK");
                        } else if received == KILL_SIGNAL_RADVD {
                            log_message(
                                &format!("Received kill radvd signal from {}", addr),
                                is_prod,
                            );
                            handle_kill_radvd(&target_ip, is_prod);
                            let _ = stream.write_all(b"OK");
                        } else if received == ADJUST_ZRAM {
                            log_message(
                                &format!("Received adjust zram signal from {}", addr),
                                is_prod,
                            );
                            handle_adjust_zram(&target_ip, is_prod);
                            let _ = stream.write_all(b"OK");
                        } else if received == KILL_SIGNAL_GOAHEAD {
                            log_message(
                                &format!("Received kill goahead signal from {}", addr),
                                is_prod,
                            );
                            handle_kill_goahead(&target_ip, is_prod);
                            let _ = stream.write_all(b"OK");
                        } else if received == USB_FUNCTIONS {
                            log_message(
                                &format!("Received usb functions query from {}", addr),
                                is_prod,
                            );
                            match fs::read_to_string("/sys/class/android_usb/android0/functions") {
                                Ok(content) => {
                                    let _ = stream.write_all(content.trim().as_bytes());
                                }
                                Err(_) => {
                                    let _ = stream.write_all(b"ERROR");
                                }
                            }
                        } else if received == WAN_IP_ADDR {
                            log_message(
                                &format!("Received get wanip query from {}", addr),
                                is_prod,
                            );
                            let wan1_ip = get_wan_ip_address(is_prod);
                            let _ = stream.write_all(wan1_ip.trim().as_bytes());
                        }
                    }
                    _ => {}
                }
            }
        }

        if now.duration_since(last_snat_check) >= Duration::from_secs(SNAT_CHECK_INTERVAL) {
            let wan1_ip = get_wan_ip_address(is_prod);

            if !wan1_ip.is_empty() && wan1_ip != current_snat_wan_ip {
                // 先添加新规则到第一行（确保新规则立即生效，对运行系统影响最小）
                let source = format!("{}/32", target_sock_ip);
                if Command::new("iptables")
                    .args(["-t", "nat", "-I", "POSTROUTING", "-s", &source, "-o", "wan1", "-j", "NETMAP", "--to", &wan1_ip])
                    .status()
                    .is_ok()
                {
                    log_message(
                        &format!("SNAT rule added: {} -> {}", target_sock_ip, wan1_ip),
                        is_prod,
                    );
                    
                    // 新规则添加成功后，删除旧规则（如果有）
                    if !current_snat_wan_ip.is_empty() {
                        if Command::new("iptables")
                            .args(["-t", "nat", "-D", "POSTROUTING", "-s", &source, "-o", "wan1", "-j", "NETMAP", "--to", &current_snat_wan_ip])
                            .status()
                            .is_ok()
                        {
                            log_message(
                                &format!("Old SNAT rule deleted: {} -> {}", target_sock_ip, current_snat_wan_ip),
                                is_prod,
                            );
                        }
                    }
                    
                    // 更新当前记录的 WAN IP
                    current_snat_wan_ip = wan1_ip;
                } else {
                    log_message(&format!("Failed to add SNAT rule to {}", wan1_ip), is_prod);
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
                        log_message(
                            &format!(
                                "High latency detected: {}ms (> {}ms)",
                                connect_duration.as_millis(),
                                HIGH_LATENCY_THRESHOLD
                            ),
                            is_prod,
                        );
                        log_message(
                            &format!(
                                "High latency count: {}/{}",
                                high_latency_count, MAX_HIGH_LATENCY
                            ),
                            is_prod,
                        );

                        send_udp_notification(
                            &format!("HIGH_LATENCY: LATENCY={:.1}", connect_duration.as_millis()),
                            target_ip.clone(),
                            is_prod,
                        );
                        if connect_duration.as_millis() > HIGH_LATENCY_THRESHOLD_MAX
                            && high_latency_count < MAX_HIGH_LATENCY
                        {
                            high_latency_count = MAX_HIGH_LATENCY
                        }

                        if high_latency_count == MAX_HIGH_LATENCY {
                            log_message(
                                &format!(
                                    "WARN: {} consecutive high latency connections detected",
                                    MAX_HIGH_LATENCY
                                ),
                                is_prod,
                            );
                            let _ = force_kill_process(is_prod, "adbd");
                            let _ = force_kill_process(is_prod, "goahead");
                            throttle_network_parameters(is_prod);
                        }
                    } else {
                        if high_latency_count >= MAX_HIGH_LATENCY {
                            if connect_duration.as_millis() < HIGH_LATENCY_THRESHOLD_MIN {
                                restore_network_parameters(is_prod);
                                let _ = force_start_goahead_process(is_prod);
                                clear_page_cache(is_prod);
                                high_latency_count = 1
                            } else {
                                high_latency_count = MAX_HIGH_LATENCY
                            }
                        } else {
                            high_latency_count = high_latency_count.saturating_sub(1);
                        }
                        send_udp_notification(
                            &format!(
                                "NORMAL_LATENCY: LATENCY={:.1}",
                                connect_duration.as_millis()
                            ),
                            target_ip.clone(),
                            is_prod,
                        );
                    }
                    failure_count = 0;
                }
                (true, None) => {
                    // 连接成功但没有获取到时间（理论上不应该发生，但需要处理）
                    log_message(
                        &format!(
                            "✓ Connection to {} successful, but duration not measured",
                            target_ip
                        ),
                        is_prod,
                    );
                    high_latency_count = 0;
                    failure_count = 0;
                }
                (false, _) => {
                    log_message(&format!("✗ Connection to {} failed", target_ip), is_prod);
                    failure_count += 1;
                    log_message(
                        &format!("Failure count: {}/{}", failure_count, MAX_FAILURES),
                        is_prod,
                    );
                    // if failure_count == WARN_FAILURES {
                    //     log_message(
                    //         &format!(
                    //             "Critical: {} consecutive pre failure detected",
                    //             WARN_FAILURES
                    //         ),
                    //         is_prod,
                    //     );
                    //     log_message("try reset android usb...", is_prod);
                    //     reset_android_usb(is_prod);
                    // } else if failure_count == MAX_FAILURES {
                    //     log_message(
                    //         &format!("Critical: {} consecutive failures detected", MAX_FAILURES),
                    //         is_prod,
                    //     );
                    //     log_message("Initiating system reboot...", is_prod);
                    //     reboot_system(is_prod);
                    // }
                }
            }
            last_network_check = now;
        }

        // KMSG 监控检查（在主循环中处理，无线程开销）
        // kmsg_monitor.check(&target_ip, is_prod);

        // 内存监控检查（在主循环中处理，无线程开销）
        memory_monitor.check(is_prod, &target_ip);

        // DNS配置检查 - 每隔120秒读取并发送dnsmasq.conf内容
        if now.duration_since(last_dns_config_check)
            >= Duration::from_secs(DNS_CONFIG_CHECK_INTERVAL)
        {
            // todo use nv get wan1_ipv6_pridns_auto
            match fs::read_to_string("/etc_rw/dnsmasq.conf") {
                Ok(content) => {
                    let msg = format!("DNS_CONF: {}", content);
                    send_udp_notification(&msg, target_ip.clone(), is_prod);
                }
                Err(e) => {
                    log_message(
                        &format!("Failed to read /etc_rw/dnsmasq.conf: {}", e),
                        is_prod,
                    );
                }
            }
            last_dns_config_check = now;
        }

        // SNTP时间同步检查
        if now.duration_since(last_sntp_check) >= Duration::from_secs(SNTP_SYNC_INTERVAL) {
            match sntp_sync_time(is_prod) {
                Ok((time_str, offset_secs, server_used)) => {
                    log_message(
                        &format!(
                            "SNTP sync successful: {} (server: {}, offset: {}s)",
                            time_str, server_used, offset_secs
                        ),
                        is_prod,
                    );
                    send_udp_notification(
                        &format!(
                            "SNTP_SYNC_OK: {} (server: {}, offset: {}s)",
                            time_str, server_used, offset_secs
                        ),
                        target_ip.clone(),
                        is_prod,
                    );
                }
                Err(e) => {
                    log_message(&format!("SNTP sync failed: {}", e), is_prod);
                    send_udp_notification(
                        &format!("SNTP_SYNC_FAILED: {}", e),
                        target_ip.clone(),
                        is_prod,
                    );
                }
            }
            last_sntp_check = now;
        }

        // 睡眠1秒后继续检查，避免忙等待
        thread::sleep(Duration::from_millis(2000));
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

fn reset_android_usb(_is_prod: bool) {
    let _ = std::fs::write("/sys/class/android_usb/android0/enable", b"0\n");
    let _ = std::fs::write("/sys/class/android_usb/android0/enable", b"1\n");
}

fn throttle_network_parameters(is_prod: bool) {
    // 调整TCP参数来减轻网络栈负担
    if let Err(e) = std::fs::write("/proc/sys/net/nf_conntrack_max", b"4096\n") {
        if !is_prod {
            log_message(
                &format!("Failed to adjust nf_conntrack_max to 4096: {}", e),
                is_prod,
            );
        }
    }
}

fn restore_network_parameters(is_prod: bool) {
    // 调整TCP参数来减轻网络栈负担
    thread::sleep(Duration::from_millis(200));
    if let Err(e) = std::fs::write("/proc/sys/net/nf_conntrack_max", b"8192\n") {
        if !is_prod {
            log_message(
                &format!("Failed to adjust nf_conntrack_max to 8192: {}", e),
                is_prod,
            );
        }
    }
}

fn get_wan_ip_address(is_prod: bool) -> String {
    // 方法1: 使用 ip 命令获取 wan1 接口的 IP
    if let Ok(output) = Command::new("ip").args(["addr", "show", "wan1"]).output() {
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

    // log_message("Could not determine wan1 IP address", is_prod);
    String::new()
}

// fn get_br_network(is_prod: bool) -> String {
//     // 获取 br0 接口的网络地址 (如 192.168.0.0/24)
//     if let Ok(output) = Command::new("ip")
//         .args(["route", "show", "dev", "br0"])
//         .output()
//     {
//         if output.status.success() {
//             let output_str = String::from_utf8_lossy(&output.stdout);
//             for line in output_str.lines() {
//                 let parts: Vec<&str> = line.trim().split_whitespace().collect();
//                 // 查找类似 "192.168.0.0/24" 的网络路由
//                 if parts.len() >= 1 && parts[0].contains('/') {
//                     let network = parts[0];
//                     if network != "default" && !network.starts_with("169.254") {
//                         // log_message(&format!("Found br0 network: {}", network), is_prod);
//                         return network.to_string();
//                     }
//                 }
//             }
//         }
//     }

//     // 如果无法获取网络地址，使用默认的 192.168.0.0/24
//     log_message(
//         "Could not determine br0 network, using default 192.168.0.0/24",
//         is_prod,
//     );
//     "192.168.0.0/24".to_string()
// }

fn optimize_network_parameters(is_prod: bool, addr: String) {
    // 调整TCP参数来减轻网络栈负担
    let ip_only = match addr.parse::<SocketAddr>() {
        Ok(sock) => sock.ip().to_string(),
        Err(_) => {
            log_message(&format!("invalid addr: {}", addr), is_prod);
            return;
        }
    };
    // let br_network = get_br_network(is_prod);
    let wan1_ip = get_wan_ip_address(is_prod);

    let commands = [
        "echo zixc_ping > /sys/power/wake_lock", 
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
        "echo 2048 > /sys/module/nf_conntrack/parameters/hashsize",
        "echo 8192 > /proc/sys/net/nf_conntrack_max",
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
        // "echo 10 > /proc/sys/net/netfilter/nf_conntrack_icmp_timeout",

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
        "echo 500 > /sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/hold_time"
    ];

    if !wan1_ip.is_empty() {
        let ipt_cmds = [
            "iptables -P INPUT ACCEPT".to_string(),
            "iptables -P FORWARD ACCEPT".to_string(),
            "iptables -P OUTPUT ACCEPT".to_string(),
            "iptables -F -t filter".to_string(),
            "iptables -F -t nat".to_string(),
            // "iptables -t nat -A POSTROUTING -s 192.168.8.2/32 -o wan1 -j MASQUERADE",
            // format!("iptables -t nat -A POSTROUTING -s {}/32 -o wan1 -j MASQUERADE", ip_only),
            // format!(
            //     "iptables -t nat -I POSTROUTING -s {}/32 -o wan1 -j SNAT --to-source {}",
            //     ip_only, wan1_ip
            // ),
            format!(
                "iptables -t nat -I POSTROUTING -s {}/32 -o wan1 -j NETMAP --to {}",
                ip_only, wan1_ip
            ),
            //&format!("iptables -t nat -A POSTROUTING -s {} -o wan1 -j MASQUERADE", br_network),
            "ip6tables -F".to_string(),
            "ifconfig wan1 txqueuelen 100".to_string(),
            // "ifconfig br0 txqueuelen 500".to_string(),
            "ifconfig usblan0 txqueuelen 500".to_string(),
        ];
        for cmd in &ipt_cmds {
            if let Err(e) = Command::new("sh").arg("-c").arg(cmd).status() {
                if !is_prod {
                    log_message(
                        &format!("Failed to adjust network parameter {}: {}", cmd, e),
                        is_prod,
                    );
                }
            }
        }
    }

    for cmd in commands.iter() {
        if let Err(e) = Command::new("sh").arg("-c").arg(cmd).status() {
            if !is_prod {
                log_message(
                    &format!("Failed to adjust network parameter {}: {}", cmd, e),
                    is_prod,
                );
            }
        }
    }
}

fn clear_page_cache(_is_prod: bool) {
    let _ = std::fs::write("/proc/sys/vm/drop_caches", b"1\n");
}

fn daemonize_simple(is_prod: bool) {
    let stdout = if is_prod {
        "/dev/null"
    } else {
        "/etc_rw/zxping.log"
    };

    let dev_null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(stdout)
        // .open("/dev/null")
        // .open("/etc_rw/zxping.log")
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
        false => (false, None),
    }
}

fn tcp_connect_check(target_ip: &str, is_prod: bool) -> bool {
    use std::net::TcpStream;

    match TcpStream::connect_timeout(&target_ip.parse().unwrap(), CONNECT_TIMEOUT) {
        Ok(stream) => {
            drop(stream);
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

    log_message(
        "All reboot attempts failed! Continuing monitoring...",
        is_prod,
    );
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
                        let _ = Command::new("/bin/kill").arg("-9").arg(&pid).status();
                        log_message(&format!("Killed adbd process (PID: {})", pid), is_prod);
                    }
                }
            }
        }
    }

    // 2. 等待一段时间确保进程完全终止
    thread::sleep(Duration::from_secs(3));

    // 3. 启动新的adbd进程
    let child = Command::new("/etc_rw/adbd")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start adbd: {}", e))?;

    // 4. 设置子进程优先级
    let pid = child.id();
    log_message(&format!("set adbd pid={} pri", pid), is_prod);
    if let Err(e) = ProcessPriority::set_nice(pid, 15) {
        log_message(
            &format!("Warning: Could not set priority for adbd: {}", e),
            is_prod,
        );
    } else {
        log_message(
            &format!("Set adbd (PID: {}) priority to nice={}", pid, 15),
            is_prod,
        );
    }

    log_message("adbd force restarted successfully", is_prod);
    let _ = re_enable_adb_function(is_prod);
    Ok(())
}

pub fn force_start_goahead_process(is_prod: bool) -> Result<(), String> {
    log_message("Force restart goahead process...", is_prod);

    // 启动进程
    let child = Command::new("/bin/goahead")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start goahead: {}", e))?;

    // 设置子进程优先级
    let pid = child.id();

    log_message(&format!("set goahead pid={} pri", pid), is_prod);
    if let Err(e) = ProcessPriority::set_nice(pid, 15) {
        log_message(
            &format!("Warning: Could not set priority for goahead: {}", e),
            is_prod,
        );
    } else {
        log_message(
            &format!("Set goahead (PID: {}) priority to nice={}", pid, 15),
            is_prod,
        );
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
                        let _ = Command::new("kill").arg("-9").arg(&pid).status();
                        log_message(&format!("force Killed process (PID: {})", pid), is_prod);
                    }
                }
            }
        }
    }

    // 2. 等待一段时间确保进程完全终止
    thread::sleep(Duration::from_secs(1));

    return Ok(());
}

/// 使用 libc::sysinfo 获取空闲内存（KB）
fn get_free_memory_kb() -> Option<u64> {
    unsafe {
        let mut info: libc::sysinfo = std::mem::zeroed();
        if libc::sysinfo(&mut info) == 0 {
            // freeram 以 mem_unit 为单位，需要转换为 KB
            let free_kb = (info.freeram as u64 * info.mem_unit as u64) / 1024;
            Some(free_kb)
        } else {
            None
        }
    }
}

// 禁用 ADB 功能（通过修改 USB 配置）
fn disable_adb_function(is_prod: bool) -> Result<(), String> {
    log_message("Disabling ADB function via USB configuration...", is_prod);
    match force_kill_process(is_prod, "adbd") {
        Ok(_) => {
            log_message("adbd killed successfully", is_prod);
        }
        Err(e) => {
            log_message(&format!("❌ Failed to kill adbd: {}", e), is_prod);
        }
    }

    std::fs::write("/sys/class/android_usb/android0/enable", b"0\n")
        .map_err(|e| format!("Failed to write enable=0: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write("/sys/class/android_usb/android0/functions", b"ecm\n")
        .map_err(|e| format!("Failed to write functions=ecm: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write("/sys/class/android_usb/android0/enable", b"1\n")
        .map_err(|e| format!("Failed to write enable=1: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write("/sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit_max", b"8192\n")
        .map_err(|e| format!("Failed to write limit_max: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write(
        "/sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit",
        b"4096\n",
    )
    .map_err(|e| format!("Failed to write limit: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write("/sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit_min", b"1024\n")
        .map_err(|e| format!("Failed to write limit_min: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write("/sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/hold_time", b"500\n")
        .map_err(|e| format!("Failed to write hold_time: {}", e))?;

    log_message("ADB function disabled, USB now in ECM mode only", is_prod);
    Ok(())
}

fn re_enable_adb_function(is_prod: bool) -> Result<(), String> {
    log_message("Re-enabling ADB function via USB configuration...", is_prod);

    std::fs::write("/sys/class/android_usb/android0/enable", b"0\n")
        .map_err(|e| format!("Failed to write enable=0: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write("/sys/class/android_usb/android0/functions", b"ecm,adb\n")
        .map_err(|e| format!("Failed to write functions=ecm,adb: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write("/sys/class/android_usb/android0/enable", b"1\n")
        .map_err(|e| format!("Failed to write enable=1: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write("/sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit_max", b"8192\n")
        .map_err(|e| format!("Failed to write limit_max: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write(
        "/sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit",
        b"4096\n",
    )
    .map_err(|e| format!("Failed to write limit: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write("/sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/limit_min", b"1024\n")
        .map_err(|e| format!("Failed to write limit_min: {}", e))?;
    thread::sleep(Duration::from_millis(100));

    std::fs::write("/sys/devices/platform/zx29_hsotg.0/gadget/net/usblan0/queues/tx-0/byte_queue_limits/hold_time", b"500\n")
        .map_err(|e| format!("Failed to write hold_time: {}", e))?;

    log_message("ADB function re-enabled, USB now in ECM+ADB mode", is_prod);
    Ok(())
}

/// 尝试从单个SNTP服务器同步时间
fn try_sntp_server(server: &str) -> Result<(u64, String), String> {
    // SNTP请求包: 48字节
    // LI (2位) + VN (3位) + Mode (3位) = 0x1B
    // LI = 0 (无闰秒), VN = 3 (版本), Mode = 3 (客户端)
    let mut request = [0u8; 48];
    request[0] = 0x1B; // LI=0, VN=3, Mode=3

    // 创建UDP socket
    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

    socket
        .set_read_timeout(Some(SNTP_TIMEOUT))
        .map_err(|e| format!("Failed to set read timeout: {}", e))?;
    socket
        .set_write_timeout(Some(SNTP_TIMEOUT))
        .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    // 发送请求
    socket
        .send_to(&request, server)
        .map_err(|e| format!("Failed to send SNTP request: {}", e))?;

    // 接收响应
    let mut response = [0u8; 48];
    let (size, _) = socket
        .recv_from(&mut response)
        .map_err(|e| format!("Failed to receive SNTP response: {}", e))?;

    if size < 48 {
        return Err("Invalid SNTP response size".to_string());
    }

    // 验证响应
    let leap_indicator = (response[0] >> 6) & 0x03;
    let version = (response[0] >> 3) & 0x07;
    let mode = response[0] & 0x07;

    if version != 3 && version != 4 {
        return Err(format!("Unsupported SNTP version: {}", version));
    }

    if mode != 4 && mode != 5 {
        return Err(format!("Invalid server mode: {}", mode));
    }

    if leap_indicator == 3 {
        return Err("Server clock not synchronized".to_string());
    }

    // 提取传输时间戳 (Transmit Timestamp: 字节 40-43: 整数部分, 字节 44-47: 小数部分)
    let seconds_since_1900 =
        u32::from_be_bytes([response[40], response[41], response[42], response[43]]) as u64;

    // SNTP时间起点是1900年1月1日，Unix时间是1970年1月1日
    // 差值: 1900-1970 = 70年 = 2208988800秒
    const NTP_UNIX_DIFF: u64 = 2208988800;

    let unix_seconds = seconds_since_1900.saturating_sub(NTP_UNIX_DIFF);

    Ok((unix_seconds, server.to_string()))
}

/// SNTP时间同步（支持多服务器）
/// 返回: (时间字符串, 与当前系统时间的偏移秒数, 使用的服务器)
fn sntp_sync_time(is_prod: bool) -> Result<(String, i64, String), String> {
    let mut last_error = String::new();

    // 尝试所有服务器，直到成功
    for server in SNTP_SERVERS {
        match try_sntp_server(server) {
            Ok((unix_seconds, server_used)) => {
                // 计算与当前系统时间的偏移
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| format!("Failed to get current time: {}", e))?
                    .as_secs() as i64;

                let offset = unix_seconds as i64 - current_time;

                // 如果时间偏差超过5秒，则调整系统时间
                if offset.abs() > 5 {
                    log_message(
                        &format!(
                            "Time offset too large ({}s), adjusting system time...",
                            offset
                        ),
                        is_prod,
                    );

                    // 使用libc::settimeofday设置系统时间
                    unsafe {
                        let tv = libc::timeval {
                            tv_sec: unix_seconds as libc::time_t,
                            tv_usec: 0,
                        };

                        // 第二个参数在Linux中已被废弃，传null即可
                        if libc::settimeofday(&tv, std::ptr::null()) != 0 {
                            let err = io::Error::last_os_error();
                            return Err(format!("settimeofday failed: {}", err));
                        }
                    }
                }

                // 格式化时间字符串 (UTC)
                // let time_str = format_unix_time(unix_seconds);

                return Ok((unix_seconds.to_string(), offset, server_used));
            }
            Err(e) => {
                last_error = format!("{}: {}", server, e);
                if !is_prod {
                    log_message(&format!("SNTP server {} failed: {}", server, e), is_prod);
                }
                // 继续尝试下一个服务器
                continue;
            }
        }
    }

    // 所有服务器都失败
    Err(format!(
        "All SNTP servers failed. Last error: {}",
        last_error
    ))
}

// /// 将Unix时间戳格式化为可读字符串
// fn format_unix_time(unix_seconds: u64) -> String {
//     // 简单的日期格式化 (不需要chrono crate)
//     const DAYS_IN_MONTH: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

//     let mut days = unix_seconds / 86400;
//     let rem_seconds = unix_seconds % 86400;

//     let hour = (rem_seconds / 3600) as u8;
//     let minute = ((rem_seconds % 3600) / 60) as u8;
//     let second = (rem_seconds % 60) as u8;

//     // 1970年1月1日起始
//     let mut year = 1970u32;

//     loop {
//         let days_in_year = if is_leap_year(year) { 366 } else { 365 };
//         if days < days_in_year {
//             break;
//         }
//         days -= days_in_year;
//         year += 1;
//     }

//     let mut month = 1u8;
//     while month <= 12 {
//         let dim = if month == 2 && is_leap_year(year) {
//             29
//         } else {
//             DAYS_IN_MONTH[(month - 1) as usize] as u64
//         };
//         if days < dim {
//             break;
//         }
//         days -= dim;
//         month += 1;
//     }

//     let day = (days + 1) as u8;

//     format!(
//         "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
//         year, month, day, hour, minute, second
//     )
// }

// fn is_leap_year(year: u32) -> bool {
//     (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
// }
