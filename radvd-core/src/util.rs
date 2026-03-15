//! Utility functions for radvd

use crate::RadvdResult;
use std::net::Ipv6Addr;
use std::time::{SystemTime, Duration};

/// Count the number of bits set in an integer
pub fn count_bits(mut b: u32) -> u32 {
    let mut count = 0;
    while b != 0 {
        count += b & 1;
        b >>= 1;
    }
    count
}

/// Simple LCG random number generator state
static mut RNG_STATE: u64 = 0;

/// Initialize RNG seed from current time
fn init_rng_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as u64,
        Err(_) => 123456789u64,
    }
}

/// Generate a random u32 using LCG (Linear Congruential Generator)
fn lcg_random() -> u32 {
    unsafe {
        if RNG_STATE == 0 {
            RNG_STATE = init_rng_seed();
        }
        // LCG parameters from Numerical Recipes
        RNG_STATE = RNG_STATE.wrapping_mul(1664525).wrapping_add(1013904223);
        RNG_STATE as u32
    }
}

/// Generate a random number between min and max
pub fn rand_between(min: f64, max: f64) -> f64 {
    if min >= max {
        return min;
    }
    let random_u32 = lcg_random();
    let normalized = random_u32 as f64 / u32::MAX as f64;
    min + normalized * (max - min)
}

/// Get current time as SystemTime
pub fn now() -> SystemTime {
    SystemTime::now()
}

/// Convert SystemTime to timespec-like seconds and nanoseconds
pub fn system_time_to_timespec(time: SystemTime) -> (i64, i64) {
    let duration = time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    (duration.as_secs() as i64, duration.subsec_nanos() as i64)
}

/// Calculate difference between two SystemTimes in milliseconds
pub fn timespec_diff_msec(a: SystemTime, b: SystemTime) -> i64 {
    let diff = if a > b {
        a.duration_since(b).unwrap_or(Duration::from_secs(0))
    } else {
        b.duration_since(a).unwrap_or(Duration::from_secs(0))
    };
    
    if a > b {
        diff.as_millis() as i64
    } else {
        -(diff.as_millis() as i64)
    }
}

/// Get the prefix from an address and mask
pub fn get_prefix6(addr: &Ipv6Addr, mask: &Ipv6Addr) -> Ipv6Addr {
    let addr_bytes = addr.octets();
    let mask_bytes = mask.octets();
    let mut result = [0u8; 16];
    
    for i in 0..16 {
        result[i] = addr_bytes[i] & mask_bytes[i];
    }
    
    Ipv6Addr::from(result)
}

/// Parse an IPv6 address string with optional prefix length
pub fn parse_prefix(s: &str) -> RadvdResult<(Ipv6Addr, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    
    let addr = parts[0]
        .parse::<Ipv6Addr>()
        .map_err(|e| crate::RadvdError::parse(format!("Invalid IPv6 address: {}", e)))?;
    
    let prefix_len = if parts.len() > 1 {
        parts[1]
            .parse::<u8>()
            .map_err(|e| crate::RadvdError::parse(format!("Invalid prefix length: {}", e)))?
    } else {
        64
    };
    
    if prefix_len > 128 {
        return Err(crate::RadvdError::parse("Prefix length must be <= 128"));
    }
    
    Ok((addr, prefix_len))
}

/// Convert IPv6 address to string with zone ID if present
pub fn addr_to_str(addr: &Ipv6Addr) -> String {
    addr.to_string()
}

/// Format an address with scope
pub fn addr_to_str_with_scope(addr: &Ipv6Addr, scope_id: u32) -> String {
    if scope_id != 0 {
        format!("{}%{})", addr, scope_id)
    } else {
        addr.to_string()
    }
}

/// Check if an address is link-local
pub fn is_link_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// Check if an address is multicast
pub fn is_multicast(addr: &Ipv6Addr) -> bool {
    addr.octets()[0] == 0xff
}

/// Check if an address is unspecified
pub fn is_unspecified(addr: &Ipv6Addr) -> bool {
    addr.is_unspecified()
}

/// Get the multicast all-nodes address
pub fn all_nodes_address() -> Ipv6Addr {
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
}

/// Get the multicast all-routers address  
pub fn all_routers_address() -> Ipv6Addr {
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2)
}

/// Get the solicited-node multicast address for a unicast address
pub fn solicited_node_multicast(addr: &Ipv6Addr) -> Ipv6Addr {
    let bytes = addr.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        0x0001,
        0xff00 | (bytes[13] as u16),
        ((bytes[14] as u16) << 8) | (bytes[15] as u16),
    )
}

/// Create a prefix mask from prefix length
pub fn prefix_len_to_mask(prefix_len: u8) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;
    
    for i in 0..full_bytes {
        bytes[i] = 0xff;
    }
    
    if full_bytes < 16 && remaining_bits > 0 {
        bytes[full_bytes] = 0xff << (8 - remaining_bits);
    }
    
    Ipv6Addr::from(bytes)
}

/// Check if address matches prefix
pub fn addr_in_prefix(addr: &Ipv6Addr, prefix: &Ipv6Addr, prefix_len: u8) -> bool {
    let mask = prefix_len_to_mask(prefix_len);
    let masked_addr = get_prefix6(addr, &mask);
    let masked_prefix = get_prefix6(prefix, &mask);
    masked_addr == masked_prefix
}

/// Read exactly n bytes from a file descriptor
#[cfg(unix)]
pub fn readn(fd: i32, buf: &mut [u8], count: usize) -> std::io::Result<usize> {
    use libc;
    
    let mut total_read = 0;
    while total_read < count {
        let n = unsafe {
            libc::read(fd, buf[total_read..].as_mut_ptr() as *mut _, count - total_read)
        };
        
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        
        if n == 0 {
            break;
        }
        
        total_read += n as usize;
    }
    
    Ok(total_read)
}

/// Write exactly n bytes to a file descriptor
#[cfg(unix)]
pub fn writen(fd: i32, buf: &[u8], count: usize) -> std::io::Result<usize> {
    use libc;
    
    let mut total_written = 0;
    while total_written < count {
        let n = unsafe {
            libc::write(fd, buf[total_written..].as_ptr() as *const _, count - total_written)
        };
        
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        
        total_written += n as usize;
    }
    
    Ok(total_written)
}

/// Format a string with printf-style formatting
pub fn formatf(format: &str, args: &[&str]) -> String {
    // Simple implementation - replace %s with args sequentially
    let mut result = format.to_string();
    for arg in args {
        if let Some(pos) = result.find("%s") {
            result.replace_range(pos..pos+2, arg);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_bits() {
        assert_eq!(count_bits(0), 0);
        assert_eq!(count_bits(1), 1);
        assert_eq!(count_bits(0b101010), 3);
        assert_eq!(count_bits(0xff), 8);
    }

    #[test]
    fn test_get_prefix6() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6);
        let mask = Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0, 0, 0, 0, 0);
        let prefix = get_prefix6(&addr, &mask);
        assert_eq!(prefix, Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0));
    }

    #[test]
    fn test_parse_prefix() {
        let (addr, len) = parse_prefix("2001:db8::/64").unwrap();
        assert_eq!(addr, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        assert_eq!(len, 64);

        let (addr, len) = parse_prefix("::1").unwrap();
        assert_eq!(addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(len, 64);
    }

    #[test]
    fn test_is_link_local() {
        assert!(is_link_local(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_link_local(&Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_prefix_len_to_mask() {
        let mask64 = prefix_len_to_mask(64);
        assert_eq!(mask64, Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0));

        let mask128 = prefix_len_to_mask(128);
        assert_eq!(mask128, Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff));
    }
}
