//! Timer utilities for radvd

use crate::config::Interface;
use crate::constants::*;
use crate::util::rand_between;
use std::time::{Duration, SystemTime};

/// Check if the interface timer has expired
pub fn expired(iface: &Interface) -> bool {
    if let Some(next) = iface.times.next_multicast {
        SystemTime::now() >= next
    } else {
        true
    }
}

/// Calculate the next multicast time
pub fn next_multicast_time(iface: &Interface) -> SystemTime {
    let now = SystemTime::now();
    
    // Calculate the delay
    let delay = if iface.state.racount < MAX_INITIAL_RTR_ADVERTISEMENTS {
        // During initialization, use shorter intervals
        let max_delay = MAX_INITIAL_RTR_ADV_INTERVAL as f64;
        rand_between(0.0, max_delay)
    } else {
        // Normal operation
        let min_interval = iface.min_rtr_adv_interval;
        let max_interval = iface.max_rtr_adv_interval;
        rand_between(min_interval, max_interval)
    };
    
    now + Duration::from_secs_f64(delay)
}

/// Calculate next time in milliseconds until RA should be sent
pub fn next_time_msec(iface: &Interface) -> u64 {
    let now = SystemTime::now();
    
    let next = if let Some(next_multicast) = iface.times.next_multicast {
        next_multicast
    } else {
        return 0;
    };
    
    if next <= now {
        0
    } else {
        let diff = next.duration_since(now).unwrap_or(Duration::from_secs(0));
        diff.as_millis() as u64
    }
}

/// Reschedule interface for next advertisement
pub fn reschedule_iface(iface: &mut Interface, next: f64) {
    let now = SystemTime::now();
    iface.times.next_multicast = Some(now + Duration::from_secs_f64(next));
}

/// Touch interface - update last_ra_time
pub fn touch_iface(iface: &mut Interface) {
    iface.times.last_ra_time = Some(SystemTime::now());
}

/// Get minimum delay between RAs
pub fn min_delay_between_ras(iface: &Interface) -> Duration {
    // Use MIPv6 minimum if mobile IPv6 is enabled
    if iface.mobile_ipv6.adv_home_agent_info || iface.mobile_ipv6.adv_interval_opt {
        Duration::from_secs_f64(MIN_DELAY_BETWEEN_RAS_MIPV6)
    } else {
        Duration::from_secs_f64(iface.min_delay_between_ras)
    }
}

/// Check if we can send an RA (respecting min delay)
pub fn can_send_ra(iface: &Interface) -> bool {
    if let Some(last_ra) = iface.times.last_ra_time {
        let min_delay = min_delay_between_ras(iface);
        SystemTime::now().duration_since(last_ra).unwrap_or(Duration::from_secs(0)) >= min_delay
    } else {
        true
    }
}

/// Calculate randomized interval according to RFC 4861
pub fn calc_rand_interval(min_interval: f64, max_interval: f64) -> f64 {
    rand_between(min_interval, max_interval)
}

/// Calculate the time to wait before sending next unsolicited RA
pub fn next_unsolicited_ra_time(iface: &Interface) -> SystemTime {
    let now = SystemTime::now();
    
    let interval = if iface.state.racount < MAX_INITIAL_RTR_ADVERTISEMENTS {
        // Use shorter intervals during initialization
        rand_between(0.0, MAX_INITIAL_RTR_ADV_INTERVAL as f64)
    } else {
        // Normal intervals
        // rand_between(0.0, MAX_INITIAL_RTR_ADV_INTERVAL as f64)
        calc_rand_interval(iface.min_rtr_adv_interval, iface.max_rtr_adv_interval)
    };
    
    now + Duration::from_secs_f64(interval)
}

/// Calculate remaining lifetime for prefix decrement
pub fn calc_remaining_lifetime(lifetime: u32, elapsed_secs: u64) -> u32 {
    if elapsed_secs >= lifetime as u64 {
        0
    } else {
        lifetime - elapsed_secs as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Interface;

    #[test]
    fn test_next_time_msec() {
        let mut iface = Interface::default();
        let now = SystemTime::now();
        
        // Future time
        iface.times.next_multicast = Some(now + Duration::from_secs(10));
        let msec = next_time_msec(&iface);
        assert!(msec > 9000 && msec <= 10000);
        
        // Past time
        iface.times.next_multicast = Some(now - Duration::from_secs(1));
        let msec = next_time_msec(&iface);
        assert_eq!(msec, 0);
    }

    #[test]
    fn test_calc_rand_interval() {
        let min = 3.0;
        let max = 10.0;
        
        for _ in 0..100 {
            let interval = calc_rand_interval(min, max);
            assert!(interval >= min && interval <= max);
        }
    }

    #[test]
    fn test_calc_remaining_lifetime() {
        assert_eq!(calc_remaining_lifetime(100, 10), 90);
        assert_eq!(calc_remaining_lifetime(100, 100), 0);
        assert_eq!(calc_remaining_lifetime(100, 150), 0);
    }
}
