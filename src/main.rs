use std::thread;
use std::time::{Duration, Instant};
use std::env;
use daemonize::Daemonize;

const DEFAULT_TARGET_IP: &str = "127.0.0.1:80";
const PING_INTERVAL: u64 = 60;
const MAX_FAILURES: u32 = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

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
        println!("Ping interval: {} seconds", PING_INTERVAL);
        println!("Reboot after {} consecutive failures", MAX_FAILURES);
        println!("Usage: {} [TARGET_IP] [--background] [--isprod]", args[0]);
    }
    
    log_message(&format!("Network monitor started for {}", target_ip), is_prod);
    
    let mut failure_count = 0;
    
    loop {
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
        
        thread::sleep(Duration::from_secs(PING_INTERVAL));
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
    
    // 跳过程序名和 --background 参数
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
            log_message(&format!("TCP connect successful, took {:?}", duration), is_prod);
            true
        }
        Err(e) => {
            log_message(&format!("TCP connect failed: {}", e), is_prod);
            false
        }
    }
}

fn reboot_system(is_prod: bool) {
    use std::process::Command;
    
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