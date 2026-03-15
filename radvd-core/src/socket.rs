//! ICMPv6 socket handling for radvd

use crate::error::{RadvdError, RadvdResult};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};

/// ICMPv6 socket wrapper
pub struct IcmpV6Socket {
    socket: socket2::Socket,
}

impl IcmpV6Socket {
    /// Open a raw ICMPv6 socket for sending/receiving Router Advertisements
    pub fn new() -> RadvdResult<Self> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV6),
        ).map_err(|e| RadvdError::socket(format!("Failed to create ICMPv6 socket: {}", e)))?;

        Ok(Self { socket })
    }

    /// Set up the socket for router advertisement operations
    pub fn setup(&self) -> RadvdResult<()> {
        // Set socket to receive hop limit
        self.set_recv_hop_limit(true)?;
        
        // Set socket to receive packet info
        self.set_recv_pktinfo(true)?;
        
        // Join the all-routers multicast group
        self.join_multicast_v6(&crate::util::all_routers_address(), 0)?;
        
        Ok(())
    }

    /// Enable/disable receiving hop limit
    pub fn set_recv_hop_limit(&self, enable: bool) -> RadvdResult<()> {
        let value: i32 = if enable { 1 } else { 0 };
        
        // IPV6_RECVHOPLIMIT
        const IPV6_RECVHOPLIMIT: libc::c_int = 51;
        
        let ret = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                IPV6_RECVHOPLIMIT,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        
        if ret < 0 {
            return Err(RadvdError::socket(format!(
                "Failed to set IPV6_RECVHOPLIMIT: {}",
                std::io::Error::last_os_error()
            )));
        }
        
        Ok(())
    }

    /// Enable/disable receiving packet info
    pub fn set_recv_pktinfo(&self, enable: bool) -> RadvdResult<()> {
        let value: i32 = if enable { 1 } else { 0 };
        
        // IPV6_RECVPKTINFO
        const IPV6_RECVPKTINFO: libc::c_int = 49;
        
        let ret = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                IPV6_RECVPKTINFO,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        
        if ret < 0 {
            return Err(RadvdError::socket(format!(
                "Failed to set IPV6_RECVPKTINFO: {}",
                std::io::Error::last_os_error()
            )));
        }
        
        Ok(())
    }

    /// Set the hop limit for outgoing unicast packets
    pub fn set_hop_limit(&self, hop_limit: i32) -> RadvdResult<()> {
        let ret = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
                &hop_limit as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        
        if ret < 0 {
            return Err(RadvdError::socket(format!(
                "Failed to set IPV6_UNICAST_HOPS: {}",
                std::io::Error::last_os_error()
            )));
        }
        
        Ok(())
    }
    
    /// Set the hop limit for outgoing multicast packets
    pub fn set_multicast_hop_limit(&self, hop_limit: i32) -> RadvdResult<()> {
        let ret = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_HOPS,
                &hop_limit as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        
        if ret < 0 {
            return Err(RadvdError::socket(format!(
                "Failed to set IPV6_MULTICAST_HOPS: {}",
                std::io::Error::last_os_error()
            )));
        }
        
        Ok(())
    }
    
    /// Enable/disable multicast loopback
    pub fn set_multicast_loop(&self, enable: bool) -> RadvdResult<()> {
        let value: i32 = if enable { 1 } else { 0 };
        
        let ret = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_LOOP,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        
        if ret < 0 {
            return Err(RadvdError::socket(format!(
                "Failed to set IPV6_MULTICAST_LOOP: {}",
                std::io::Error::last_os_error()
            )));
        }
        
        Ok(())
    }
    
    /// Set kernel checksum calculation offset for ICMPv6
    pub fn set_checksum(&self, offset: i32) -> RadvdResult<()> {
        let ret = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::IPPROTO_RAW,
                libc::IPV6_CHECKSUM,
                &offset as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        
        if ret < 0 {
            // Try IPPROTO_IPV6 if IPPROTO_RAW fails
            let ret2 = unsafe {
                libc::setsockopt(
                    self.socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_CHECKSUM,
                    &offset as *const _ as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                )
            };
            
            if ret2 < 0 {
                return Err(RadvdError::socket(format!(
                    "Failed to set IPV6_CHECKSUM: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        
        Ok(())
    }

    /// Join an IPv6 multicast group
    pub fn join_multicast_v6(&self, addr: &Ipv6Addr, interface_index: u32) -> RadvdResult<()> {
        self.socket
            .join_multicast_v6(addr, interface_index)
            .map_err(|e| RadvdError::socket(format!("Failed to join multicast group: {}", e)))
    }

    /// Leave an IPv6 multicast group
    pub fn leave_multicast_v6(&self, addr: &Ipv6Addr, interface_index: u32) -> RadvdResult<()> {
        self.socket
            .leave_multicast_v6(addr, interface_index)
            .map_err(|e| RadvdError::socket(format!("Failed to leave multicast group: {}", e)))
    }

    /// Bind to all routers multicast address
    pub fn bind_to_all_routers(&self) -> RadvdResult<()> {
        let addr = SocketAddrV6::new(crate::util::all_routers_address(), 0, 0, 0);
        let sock_addr = socket2::SockAddr::from(addr);
        self.socket
            .bind(&sock_addr)
            .map_err(|e| RadvdError::socket(format!("Failed to bind socket: {}", e)))
    }

    /// Send data on the socket
    pub fn send_to(&self, buf: &[u8], addr: &SocketAddrV6) -> RadvdResult<usize> {
        let sock_addr = socket2::SockAddr::from(*addr);
        self.socket
            .send_to(buf, &sock_addr)
            .map_err(|e| RadvdError::socket(format!("Failed to send: {}", e)))
    }

    /// Receive data from the socket
    pub fn recv_from(&self, buf: &mut [u8]) -> RadvdResult<(usize, SocketAddrV6)> {
        // Use MaybeUninit for socket2 compatibility
        let mut uninit_buf: Vec<std::mem::MaybeUninit<u8>> = 
            buf.iter().map(|&b| std::mem::MaybeUninit::new(b)).collect();
        
        let (len, addr) = self.socket
            .recv_from(&mut uninit_buf)
            .map_err(|e| RadvdError::socket(format!("Failed to receive: {}", e)))?;
        
        // Copy received data back to buf
        for i in 0..len {
            buf[i] = unsafe { uninit_buf[i].assume_init() };
        }
        
        let addr_v6 = match addr.as_socket() {
            Some(std::net::SocketAddr::V6(a)) => a,
            _ => return Err(RadvdError::socket("Received non-IPv6 address")),
        };
        
        Ok((len, addr_v6))
    }

    /// Get the raw file descriptor
    pub fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Set socket as non-blocking
    pub fn set_nonblocking(&self, nonblocking: bool) -> RadvdResult<()> {
        self.socket
            .set_nonblocking(nonblocking)
            .map_err(|e| RadvdError::socket(format!("Failed to set nonblocking: {}", e)))
    }

    /// Set SO_REUSEADDR
    pub fn set_reuse_addr(&self, reuse: bool) -> RadvdResult<()> {
        self.socket
            .set_reuse_address(reuse)
            .map_err(|e| RadvdError::socket(format!("Failed to set SO_REUSEADDR: {}", e)))
    }

    /// Bind to device (Linux specific)
    #[cfg(target_os = "linux")]
    pub fn bind_to_device(&self, iface_name: &str) -> RadvdResult<()> {
        self.socket
            .bind_device(Some(iface_name.as_bytes()))
            .map_err(|e| RadvdError::socket(format!("Failed to bind to device: {}", e)))
    }
}

/// Open and configure an ICMPv6 socket for router advertisements
pub fn open_icmpv6_socket() -> RadvdResult<IcmpV6Socket> {
    let socket = IcmpV6Socket::new()?;
    
    // Set hop limit to 255 (required for ND packets)
    socket.set_hop_limit(255)?;
    
    // Set multicast hop limit to 255
    socket.set_multicast_hop_limit(255)?;
    
    // Disable multicast loopback
    socket.set_multicast_loop(false)?;
    
    // Enable kernel checksum calculation for ICMPv6 (offset 2)
    socket.set_checksum(2)?;
    
    // Set up socket options
    socket.setup()?;
    
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_creation() {
        let socket = IcmpV6Socket::new();
        assert!(socket.is_ok());
    }
}
