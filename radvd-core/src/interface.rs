//! Interface management for radvd

use crate::config::{AdvDnssl, AdvPrefix, AdvRdnss, AdvRoute, Interface};
use crate::constants::*;
use crate::error::{RadvdError, RadvdResult};
use crate::util::*;
use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;

/// Initialize interface with default values
pub fn iface_init_defaults(iface: &mut Interface) {
    // Set default values for all fields
    *iface = Interface::default();
}

/// Initialize prefix with default values
pub fn prefix_init_defaults(prefix: &mut AdvPrefix) {
    *prefix = AdvPrefix::default();
}

/// Initialize RDNSS with default values
pub fn rdnss_init_defaults(rdnss: &mut AdvRdnss, iface: &Interface) {
    rdnss.adv_rdnss_lifetime = dflt_adv_rdnss_lifetime(iface.max_rtr_adv_interval) as u32;
}

/// Initialize DNSSL with default values
pub fn dnssl_init_defaults(dnssl: &mut AdvDnssl, iface: &Interface) {
    dnssl.adv_dnssl_lifetime = dflt_adv_dnssl_lifetime(iface.max_rtr_adv_interval) as u32;
}

/// Initialize route with default values
pub fn route_init_defaults(route: &mut AdvRoute, iface: &Interface) {
    route.adv_route_lifetime = dflt_adv_route_lifetime(iface.max_rtr_adv_interval);
}

/// Check if interface is properly configured
pub fn check_iface(iface: &Interface) -> RadvdResult<()> {
    // Check if interface name is set
    if iface.props.name.is_empty() {
        return Err(RadvdError::interface("Interface name not set"));
    }

    // Check if sending advertisements is enabled
    if !iface.adv_send_advert {
        return Err(RadvdError::interface(format!(
            "AdvSendAdvert is off for interface {}",
            iface.props.name
        )));
    }

    // Validate the interface configuration
    iface.validate()?;

    Ok(())
}

/// Find interface by index
pub fn find_iface_by_index<'a>(ifaces: &'a [Interface], index: u32) -> Option<&'a Interface> {
    ifaces.iter().find(|iface| iface.props.if_index == index)
}

/// Find interface by name
pub fn find_iface_by_name<'a>(ifaces: &'a [Interface], name: &str) -> Option<&'a Interface> {
    ifaces.iter().find(|iface| iface.props.name == name)
}

/// Find mutable interface by name
pub fn find_iface_by_name_mut<'a>(ifaces: &'a mut [Interface], name: &str) -> Option<&'a mut Interface> {
    ifaces.iter_mut().find(|iface| iface.props.name == name)
}

/// Find interface that needs to send RA next
pub fn find_iface_by_time(ifaces: &[Interface]) -> Option<&Interface> {
    let mut earliest_iface: Option<&Interface> = None;
    let mut earliest_time: Option<std::time::SystemTime> = None;
    
    for iface in ifaces {
        if let Some(next) = iface.times.next_multicast {
            if earliest_time.is_none() || next < earliest_time.unwrap() {
                earliest_time = Some(next);
                earliest_iface = Some(iface);
            }
        }
    }
    
    earliest_iface
}

/// Iterate over all interfaces and apply a function
pub fn for_each_iface<F>(ifaces: &mut [Interface], mut f: F)
where
    F: FnMut(&mut Interface),
{
    for iface in ifaces {
        f(iface);
    }
}

/// Set up interface for router advertisements
pub fn setup_iface(_sock: &crate::socket::IcmpV6Socket, iface: &mut Interface) -> RadvdResult<()> {
    // Check if interface is ready
    check_iface(iface)?;
    
    // Mark interface as ready
    iface.state.ready = true;
    iface.state.changed = false;
    
    // Reset racount
    iface.state.racount = 0;
    
    // Schedule first advertisement
    crate::timer::reschedule_iface(iface, 0.0);
    
    Ok(())
}

/// Clean up interface
pub fn cleanup_iface(_sock: &crate::socket::IcmpV6Socket, iface: &mut Interface) -> RadvdResult<()> {
    if iface.remove_adv_on_exit && iface.state.ready {
        // Send final RA with zero lifetimes
        iface.state.cease_adv = true;
        // The actual sending will be done by the caller
    }
    
    iface.state.ready = false;
    
    Ok(())
}

/// Get interface index by name (Linux)
#[cfg(target_os = "linux")]
pub fn get_iface_index(name: &str) -> RadvdResult<u32> {
    let sock = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)
        .map_err(|e| RadvdError::interface(format!("Failed to create socket: {}", e)))?;
    
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    
    // Copy interface name
    let bytes = name.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i >= ifr.ifr_name.len() - 1 {
            break;
        }
        ifr.ifr_name[i] = b as libc::c_char;
    }
    
    let ret = unsafe {
        libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFINDEX as _, &ifr)
    };
    
    if ret < 0 {
        return Err(RadvdError::interface(format!(
            "Failed to get interface index for {}: {}",
            name,
            std::io::Error::last_os_error()
        )));
    }
    
    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex } as u32)
}

/// Get interface link-local address
pub fn get_iface_link_local_addr(_name: &str) -> RadvdResult<Ipv6Addr> {
    use std::net::UdpSocket;
    
    // Connect to a link-local destination to get our link-local address
    let sock = UdpSocket::bind("[::]:0")
        .map_err(|e| RadvdError::interface(format!("Failed to bind socket: {}", e)))?;
    
    // Try to connect to link-local all-nodes address
    sock.connect("[ff02::1%en0]:1")
        .or_else(|_| sock.connect("[ff02::1]:1"))
        .map_err(|e| RadvdError::interface(format!("Failed to connect: {}", e)))?;
    
    let local_addr = sock
        .local_addr()
        .map_err(|e| RadvdError::interface(format!("Failed to get local address: {}", e)))?;
    
    match local_addr {
        std::net::SocketAddr::V6(addr) => Ok(*addr.ip()),
        _ => Err(RadvdError::interface("Failed to get IPv6 address")),
    }
}

/// Get all interface addresses
pub fn get_iface_addrs(name: &str) -> RadvdResult<Vec<Ipv6Addr>> {
    // Use getifaddrs on Unix systems
    let mut addrs = Vec::new();
    
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        
        if libc::getifaddrs(&mut ifap) < 0 {
            return Err(RadvdError::interface(format!(
                "getifaddrs failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        
        let mut ifa = ifap;
        while !ifa.is_null() {
            let ifa_ref = &*ifa;
            
            // Check if this is our interface and an AF_INET6 address
            let ifa_name = std::ffi::CStr::from_ptr(ifa_ref.ifa_name);
            if ifa_name.to_string_lossy() == name && !ifa_ref.ifa_addr.is_null() {
                let addr = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in6);
                if addr.sin6_family as i32 == libc::AF_INET6 {
                    let ipv6_addr = Ipv6Addr::from(addr.sin6_addr.s6_addr);
                    addrs.push(ipv6_addr);
                }
            }
            
            ifa = ifa_ref.ifa_next;
        }
        
        libc::freeifaddrs(ifap);
    }
    
    Ok(addrs)
}

/// Check if interface exists
pub fn iface_exists(name: &str) -> bool {
    get_iface_index(name).is_ok()
}

/// Get interface hardware address
#[cfg(target_os = "linux")]
pub fn get_iface_hwaddr(name: &str) -> RadvdResult<(Vec<u8>, i32)> {
    let sock = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)
        .map_err(|e| RadvdError::interface(format!("Failed to create socket: {}", e)))?;
    
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    
    // Copy interface name
    let bytes = name.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i >= ifr.ifr_name.len() - 1 {
            break;
        }
        ifr.ifr_name[i] = b as libc::c_char;
    }
    
    let ret = unsafe {
        libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR as _, &ifr)
    };
    
    if ret < 0 {
        return Err(RadvdError::interface(format!(
            "Failed to get hardware address for {}: {}",
            name,
            std::io::Error::last_os_error()
        )));
    }
    
    // Extract hardware address
    let hwaddr = unsafe { ifr.ifr_ifru.ifru_hwaddr };
    let sa_family = hwaddr.sa_family as i32;
    let addr_len = match sa_family as u16 {
        libc::ARPHRD_ETHER => 6,
        _ => 0,
    };
    
    let addr_bytes: Vec<u8> = hwaddr.sa_data.iter()
            .take(addr_len as usize)
            .map(|&b| b as u8)
            .collect();
    
    Ok((addr_bytes, addr_len))
}

/// Get interface MTU
pub fn get_iface_mtu(name: &str) -> RadvdResult<u32> {
    let sock = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)
        .map_err(|e| RadvdError::interface(format!("Failed to create socket: {}", e)))?;
    
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    
    // Copy interface name
    let bytes = name.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i >= ifr.ifr_name.len() - 1 {
            break;
        }
        ifr.ifr_name[i] = b as libc::c_char;
    }
    
    let ret = unsafe {
        libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU as _, &ifr)
    };
    
    if ret < 0 {
        return Err(RadvdError::interface(format!(
            "Failed to get MTU for {}: {}",
            name,
            std::io::Error::last_os_error()
        )));
    }
    
    Ok(unsafe { ifr.ifr_ifru.ifru_mtu } as u32)
}

/// Update interface device index
pub fn update_device_index(iface: &mut Interface) -> RadvdResult<()> {
    iface.props.if_index = get_iface_index(&iface.props.name)?;
    Ok(())
}

/// Update interface device information
pub fn update_device_info(_sock: &crate::socket::IcmpV6Socket, iface: &mut Interface) -> RadvdResult<()> {
    // Update index
    update_device_index(iface)?;
    
    // Get addresses
    let addrs = get_iface_addrs(&iface.props.name)?;
    
    // Find link-local address
    for addr in &addrs {
        if is_link_local(addr) {
            iface.props.if_addr = *addr;
            break;
        }
    }
    
    iface.props.if_addrs = addrs;
    
    // Get hardware address for SLLAO
    #[cfg(target_os = "linux")]
    {
        let (hwaddr, len) = get_iface_hwaddr(&iface.props.name)?;
        iface.sllao.if_hwaddr[..hwaddr.len()].copy_from_slice(&hwaddr);
        iface.sllao.if_hwaddr_len = len;
        
        // Set prefix length based on type
        iface.sllao.if_prefix_len = if len == 6 { 64 } else { 0 };
    }
    
    // Get MTU
    iface.sllao.if_maxmtu = get_iface_mtu(&iface.props.name)? as i32;
    
    Ok(())
}
