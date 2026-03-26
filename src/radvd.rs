use radvd_core::config::{AdvPrefix, Config, Interface};
use std::net::Ipv6Addr;

use radvd_core::constants::{MAX_INITIAL_RTR_ADVERTISEMENTS, MAX_INITIAL_RTR_ADV_INTERVAL};
use radvd_core::interface::{self, update_device_info};
use radvd_core::ra::send_ra_forall;
use radvd_core::socket::IcmpV6Socket;
use radvd_core::timer::{expired, reschedule_iface, touch_iface};
use radvd_core::util::rand_between;

pub fn create_radvd_config(prefix_addr: &str, iface_name: &str) -> Config {
    use radvd_core::config::Interface;

    let mut iface = Interface::default();
    iface.props.name = iface_name.to_string();
    iface.adv_send_advert = true;
    iface.ra_header_info.adv_other_config_flag = false;
    iface.min_rtr_adv_interval = 30.0;
    iface.max_rtr_adv_interval = 100.0;

    // 添加 prefix
    let mut prefix = AdvPrefix::default();
    prefix.prefix = prefix_addr.parse().unwrap();
    prefix.prefix_len = 64;
    prefix.adv_on_link_flag = true;
    prefix.adv_autonomous_flag = true;
    prefix.adv_valid_lifetime = 300;
    prefix.adv_preferred_lifetime = 120;
    iface.adv_prefix_list.push(prefix);

    Config {
        interfaces: vec![iface],
    }
}

pub fn update_radvd_prefix(conf: &mut Config, new_prefix: &str) -> Result<(), String> {
    if let Some(iface) = conf.interfaces.first_mut() {
        if let Some(prefix) = iface.adv_prefix_list.first_mut() {
            prefix.prefix = match new_prefix.parse() {
                Ok(p) => p,
                Err(_) => return Err("前缀格式错误".to_string()),
            };
            return Ok(());
        }
    }
    Err("无法找到接口或前缀配置".to_string())
}

pub fn get_radvd_prefix() -> String {
    use std::process::Command;
    use std::str;

    // 尝试 nv 命令
    if let Ok(output) = Command::new("nv")
        .args(["get", "wan1_ipv6_prefix_info"])
        .output()
    {
        if output.status.success() {
            if let Ok(prefix) = str::from_utf8(&output.stdout) {
                let prefix = prefix.trim();
                if !prefix.is_empty() {
                    return format!("{}::", prefix.trim_end_matches(':'));
                }
            }
        }
    }

    // 从 ip 命令输出中提取前缀
    if let Ok(output) = Command::new("ip")
        .args(["-6", "addr", "show", "wan1"])
        .output()
    {
        if output.status.success() {
            if let Ok(output_str) = str::from_utf8(&output.stdout) {
                // 查找 inet6 地址行
                for line in output_str.lines() {
                    if let Some(pos) = line.find("inet6 ") {
                        let after = &line[pos + 6..];
                        let end = after
                            .find(|c: char| c == ' ' || c == '/')
                            .unwrap_or(after.len());
                        let addr = &after[..end];

                        // 跳过链路本地地址
                        if addr.starts_with("fe80") {
                            continue;
                        }

                        // 提取前4段
                        let segs: Vec<&str> = addr.split(':').collect();
                        if segs.len() >= 4 {
                            return format!("{}:{}:{}:{}::", segs[0], segs[1], segs[2], segs[3]);
                        }
                    }
                }
            }
        }
    }

    String::new()
}

fn init_interface(socket: &IcmpV6Socket, iface: &mut Interface) -> Result<(), String> {
    log(&format!("Initializing interface {}", iface.props.name));

    // Check if interface exists
    if let Err(e) = interface::update_device_index(iface) {
        if iface.ignore_if_missing {
            log(&format!(
                "Warning: Interface {} not available: {}",
                iface.props.name, e
            ));
            return Ok(());
        } else {
            return Err(format!("Interface {}: {}", iface.props.name, e));
        }
    }

    // Update device info
    if let Err(e) = update_device_info(socket, iface) {
        log(&format!(
            "Warning: Failed to get device info for {}: {}",
            iface.props.name, e
        ));
    }

    // Mark as ready
    iface.state.ready = true;
    iface.state.racount = 0;

    // Schedule first RA with small delay (IFACE_SETUP_DELAY = 1s in C code)
    // This ensures quick initial advertisement for client autoconfiguration
    reschedule_iface(iface, 1.0);

    log(&format!(
        "Interface {} ready (index={}, initial_delay=1.0s)",
        iface.props.name, iface.props.if_index
    ));

    Ok(())
}

/// Simple logger that prints to stderr
fn log(msg: &str) {
    eprintln!("[radvd] {}", msg);
}

pub fn setup_radvd(config: &mut Config, socket: &IcmpV6Socket) {
    // Create ICMPv6 socket
    // let socket = match open_icmpv6_socket() {
    //     Ok(sock) => sock,
    //     Err(e) => {
    //         eprintln!("Failed to create ICMPv6 socket: {} - are you running as root?", e);
    //         std::process::exit(1);
    //     }
    // };
    // Set socket to non-blocking mode for select/poll
    let _ = socket.set_nonblocking(true);

    log("ICMPv6 socket created successfully");

    // Initialize interfaces
    for iface in &mut config.interfaces {
        if let Err(e) = init_interface(&socket, iface) {
            eprintln!("Failed to initialize interface {}: {}", iface.props.name, e);
        }
    }
    // Main event loop
    // log("Entering main event loop");
    // run_main_loop(&mut config, &socket);
}

/// Main event loop - handles both periodic RAs and RS responses
pub fn process_radvd_socket(config: &mut Config, socket: &IcmpV6Socket, recv_buf: &mut [u8]) {
    // let mut recv_buf = vec![0u8; 1500];

    // Set socket to non-blocking mode for select/poll
    // let _ = socket.set_nonblocking(true);

    // loop {
    // Process expired timers and send RAs
    process_timers(config, socket);

    // Calculate next timer expiration
    let next_timer_ms = get_next_timer_ms(&config.interfaces);
    let timeout_ms = next_timer_ms.max(10).min(1000) as i64;

    // Use select to wait for socket data with timeout
    let fd = socket.as_raw_fd();
    let mut read_fds: libc::fd_set = unsafe { std::mem::zeroed() };

    unsafe {
        libc::FD_ZERO(&mut read_fds);
        libc::FD_SET(fd, &mut read_fds);
    }

    let mut timeout = libc::timeval {
        tv_sec: (timeout_ms / 1000) as libc::time_t,
        tv_usec: ((timeout_ms % 1000) * 1000) as libc::suseconds_t,
    };

    let ret = unsafe {
        libc::select(
            fd + 1,
            &mut read_fds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut timeout,
        )
    };

    if ret > 0 {
        // Socket is readable - receive packet
        match socket.recv_from(recv_buf) {
            Ok((len, src_addr)) => {
                // Get interface index from socket address
                let iface_index = src_addr.scope_id();
                if let Err(e) =
                    process_packet(config, &recv_buf[..len], src_addr.ip(), iface_index, socket)
                {
                    // Silently ignore packet errors
                    let _ = e;
                }
            }
            Err(_) => {
                // Receive error, continue
            }
        }
    }
    // If ret == 0, timeout occurred - continue to process timers
    // If ret < 0, error occurred - continue anyway
    // }
}

/// Process expired timers and send multicast RAs
fn process_timers(config: &mut Config, socket: &IcmpV6Socket) {
    for iface in &mut config.interfaces {
        if !iface.state.ready {
            continue;
        }

        if expired(iface) {
            // Bind socket to specific interface before sending
            if let Err(e) = socket.bind_to_device(&iface.props.name) {
                log(&format!(
                    "Failed to bind to device {}: {}",
                    iface.props.name, e
                ));
                continue;
            }

            // Send the RA
            if let Err(e) = send_ra_forall(socket, iface, None) {
                log(&format!(
                    "Failed to send RA for {}: {}",
                    iface.props.name, e
                ));
            } else {
                // Update racount BEFORE calculating next interval
                // racount is consumed in reschedule to determine when to send
                if iface.state.racount < MAX_INITIAL_RTR_ADVERTISEMENTS {
                    iface.state.racount += 1;
                }

                // Calculate next interval
                // During initial phase: use MAX_INITIAL_RTR_ADV_INTERVAL (16s)
                // Normal phase: use random between min/max interval
                let next_interval = if iface.state.racount < MAX_INITIAL_RTR_ADVERTISEMENTS {
                    MAX_INITIAL_RTR_ADV_INTERVAL as f64
                } else {
                    rand_between(iface.min_rtr_adv_interval, iface.max_rtr_adv_interval)
                };

                touch_iface(iface);
                reschedule_iface(iface, next_interval);

                // log(&format!(
                //     "Sent RA for {} (racount={}, next in {:.1}s)",
                //     iface.props.name, iface.state.racount, next_interval
                // ));
            }
        }
    }
}

/// Process a received ICMPv6 packet
fn process_packet(
    config: &mut Config,
    data: &[u8],
    src: &Ipv6Addr,
    iface_index: u32,
    socket: &IcmpV6Socket,
) -> Result<(), String> {
    // Minimum ICMPv6 header size
    if data.len() < 4 {
        return Ok(());
    }

    let icmp_type = data[0];
    let icmp_code = data[1];

    // Check for Router Solicitation (type 133)
    if icmp_type != 133 || icmp_code != 0 {
        // Not an RS, ignore
        return Ok(());
    }

    // Find matching interface
    let iface = match config
        .interfaces
        .iter_mut()
        .find(|i| i.props.if_index == iface_index)
    {
        Some(iface) => iface,
        None => return Ok(()),
    };

    if !iface.state.ready {
        return Ok(());
    }

    // Check if we should respond to this RS
    let src_unspecified = src.is_unspecified();
    if iface.unicast_only && src_unspecified {
        return Ok(());
    }

    // Bind socket to specific interface before sending
    if let Err(e) = socket.bind_to_device(&iface.props.name) {
        log(&format!(
            "Failed to bind to device {}: {}",
            iface.props.name, e
        ));
        return Ok(());
    }

    // Send solicited RA
    let dest = if src_unspecified {
        None // Multicast response
    } else {
        Some(*src) // Unicast response
    };

    if let Err(e) = send_ra_forall(socket, iface, dest.as_ref()) {
        log(&format!(
            "Failed to send solicited RA for {}: {}",
            iface.props.name, e
        ));
    } else {
        // log(&format!(
        //     "Sent solicited RA to {:?} for {}",
        //     dest, iface.props.name
        // ));
    }

    Ok(())
}

// Helper function to get next timer expiration in ms
fn get_next_timer_ms(interfaces: &[Interface]) -> u64 {
    let mut min_msec: u64 = 1000;
    for iface in interfaces {
        if !iface.state.ready {
            continue;
        }
        let msec = radvd_core::timer::next_time_msec(iface);
        if msec < min_msec {
            min_msec = msec;
        }
    }
    min_msec
}
