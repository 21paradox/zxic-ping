//! Router Advertisement (RA) packet building and sending

use crate::config::*;
use crate::constants::*;
use crate::error::RadvdResult;
use crate::types::*;
use crate::util::*;
use std::net::{Ipv6Addr, SocketAddrV6};

// ND option types
const ND_OPT_SOURCE_LINK_LAYER_ADDRESS: u8 = 1;
const ND_OPT_PREFIX_INFORMATION: u8 = 3;
const ND_OPT_MTU: u8 = 5;

/// Router Advertisement packet header (ICMPv6)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RaHeader {
    /// ICMPv6 type (134 for RA)
    pub icmp6_type: u8,
    /// ICMPv6 code
    pub icmp6_code: u8,
    /// Checksum
    pub icmp6_checksum: u16,
    /// Hop limit (0 = unspecified)
    pub cur_hop_limit: u8,
    /// M, O, H, Prf, Reserved flags
    pub flags: u8,
    /// Router lifetime (seconds)
    pub router_lifetime: u16,
    /// Reachable time (milliseconds)
    pub reachable_time: u32,
    /// Retransmit timer (milliseconds)
    pub retrans_timer: u32,
}

impl RaHeader {
    pub fn new(iface: &Interface, cease: bool) -> Self {
        let ra_info = &iface.ra_header_info;
        
        let lifetime = if cease {
            0
        } else {
            iface.default_lifetime()
        };
        
        let mut flags = 0u8;
        if ra_info.adv_managed_flag {
            flags |= 0x80; // M flag
        }
        if ra_info.adv_other_config_flag {
            flags |= 0x40; // O flag
        }
        if ra_info.adv_home_agent_flag {
            flags |= 0x20; // H flag
        }
        
        // Router preference in bits 3-4
        flags |= ra_info.adv_default_preference.as_u8_for_ra();
        
        Self {
            icmp6_type: 134, // ICMPv6 Router Advertisement
            icmp6_code: 0,
            icmp6_checksum: 0, // Will be calculated by kernel
            cur_hop_limit: ra_info.adv_cur_hop_limit,
            flags,
            router_lifetime: lifetime.to_be(),
            reachable_time: ra_info.adv_reachable_time.to_be(),
            retrans_timer: ra_info.adv_retrans_timer.to_be(),
        }
    }
    
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0] = self.icmp6_type;
        bytes[1] = self.icmp6_code;
        // 已经在 new() 中调用 to_be()，这里直接转 bytes
        bytes[2..4].copy_from_slice(&self.icmp6_checksum.to_ne_bytes());
        bytes[4] = self.cur_hop_limit;
        bytes[5] = self.flags;
        bytes[6..8].copy_from_slice(&self.router_lifetime.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.reachable_time.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.retrans_timer.to_ne_bytes());
        bytes
    }
}

/// Prefix Information option (Type 3)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PrefixInformation {
    /// Option type (3)
    pub nd_opt_pi_type: u8,
    /// Length in units of 8 octets (4)
    pub nd_opt_pi_len: u8,
    /// Prefix length in bits
    pub nd_opt_pi_prefix_len: u8,
    /// L, A, R flags
    pub nd_opt_pi_flags: u8,
    /// Valid lifetime (seconds)
    pub nd_opt_pi_valid_time: u32,
    /// Preferred lifetime (seconds)
    pub nd_opt_pi_preferred_time: u32,
    /// Reserved
    pub nd_opt_pi_reserved2: u32,
    /// Prefix
    pub nd_opt_pi_prefix: Ipv6Addr,
}

impl PrefixInformation {
    pub fn new(prefix: &AdvPrefix, cease: bool) -> Self {
        let mut flags = 0u8;
        if prefix.adv_on_link_flag {
            flags |= 0x80; // L flag
        }
        if prefix.adv_autonomous_flag {
            flags |= 0x40; // A flag
        }
        if prefix.adv_router_addr {
            flags |= ND_OPT_PI_FLAG_RADDR; // R flag
        }
        
        Self {
            nd_opt_pi_type: ND_OPT_PREFIX_INFORMATION,
            nd_opt_pi_len: 4,
            nd_opt_pi_prefix_len: prefix.prefix_len,
            nd_opt_pi_flags: flags,
            nd_opt_pi_valid_time: prefix.effective_valid_lifetime(cease).to_be(),
            nd_opt_pi_preferred_time: prefix.effective_preferred_lifetime(cease).to_be(),
            nd_opt_pi_reserved2: 0,
            nd_opt_pi_prefix: prefix.prefix,
        }
    }
    
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = self.nd_opt_pi_type;
        bytes[1] = self.nd_opt_pi_len;
        bytes[2] = self.nd_opt_pi_prefix_len;
        bytes[3] = self.nd_opt_pi_flags;
        // 已经在 new() 中调用 to_be()，这里直接转 bytes
        bytes[4..8].copy_from_slice(&self.nd_opt_pi_valid_time.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.nd_opt_pi_preferred_time.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.nd_opt_pi_reserved2.to_ne_bytes());
        bytes[16..32].copy_from_slice(&self.nd_opt_pi_prefix.octets());
        bytes
    }
}

/// MTU option (Type 5)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MtuOption {
    /// Option type (5)
    pub nd_opt_mtu_type: u8,
    /// Length in units of 8 octets (1)
    pub nd_opt_mtu_len: u8,
    /// Reserved
    pub nd_opt_mtu_reserved: u16,
    /// MTU
    pub nd_opt_mtu_mtu: u32,
}

impl MtuOption {
    pub fn new(mtu: u32) -> Self {
        Self {
            nd_opt_mtu_type: ND_OPT_MTU,
            nd_opt_mtu_len: 1,
            nd_opt_mtu_reserved: 0,
            nd_opt_mtu_mtu: mtu.to_be(),
        }
    }
    
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.nd_opt_mtu_type;
        bytes[1] = self.nd_opt_mtu_len;
        // 已经在 new() 中调用 to_be()，这里直接转 bytes
        bytes[2..4].copy_from_slice(&self.nd_opt_mtu_reserved.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.nd_opt_mtu_mtu.to_ne_bytes());
        bytes
    }
}

/// Source Link-Layer Address option (Type 1)
#[derive(Debug, Clone)]
pub struct SllaoOption {
    pub nd_opt_slla_type: u8,
    pub nd_opt_slla_len: u8,
    pub nd_opt_slla_addr: Vec<u8>,
}

impl SllaoOption {
    pub fn new(hwaddr: &[u8]) -> Self {
        let len = ((hwaddr.len() + 2 + 7) / 8) as u8; // Round up to 8-byte units
        Self {
            nd_opt_slla_type: ND_OPT_SOURCE_LINK_LAYER_ADDRESS,
            nd_opt_slla_len: len,
            nd_opt_slla_addr: hwaddr.to_vec(),
        }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_len = self.nd_opt_slla_len as usize * 8;
        let mut bytes = vec![0u8; total_len];
        bytes[0] = self.nd_opt_slla_type;
        bytes[1] = self.nd_opt_slla_len;
        bytes[2..2 + self.nd_opt_slla_addr.len()].copy_from_slice(&self.nd_opt_slla_addr);
        bytes
    }
}

/// Route Information option (Type 24)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RouteInfoOption {
    pub nd_opt_ri_type: u8,
    pub nd_opt_ri_len: u8,
    pub nd_opt_ri_prefix_len: u8,
    pub nd_opt_ri_flags: u8,
    pub nd_opt_ri_lifetime: u32,
    pub nd_opt_ri_prefix: Ipv6Addr,
}

impl RouteInfoOption {
    pub fn new(route: &AdvRoute, _iface: &Interface, cease: bool) -> Self {
        let lifetime = if cease { 0 } else { route.adv_route_lifetime };
        
        // Preference in bits 3-4
        let pref = ((route.adv_route_preference as u8) << 3) & ND_OPT_RI_PRF_MASK;
        
        Self {
            nd_opt_ri_type: ND_OPT_ROUTE_INFORMATION,
            nd_opt_ri_len: if route.prefix_len > 64 { 2 } else { 1 },
            nd_opt_ri_prefix_len: route.prefix_len,
            nd_opt_ri_flags: pref,
            nd_opt_ri_lifetime: lifetime.to_be(),
            nd_opt_ri_prefix: route.prefix,
        }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_len = self.nd_opt_ri_len as usize * 8;
        let mut bytes = vec![0u8; total_len];
        bytes[0] = self.nd_opt_ri_type;
        bytes[1] = self.nd_opt_ri_len;
        bytes[2] = self.nd_opt_ri_prefix_len;
        bytes[3] = self.nd_opt_ri_flags;
        // 已经在 new() 中调用 to_be()，这里直接转 bytes
        bytes[4..8].copy_from_slice(&self.nd_opt_ri_lifetime.to_ne_bytes());
        
        // Copy prefix bytes based on length
        let prefix_bytes = if self.nd_opt_ri_prefix_len > 64 { 16 } else { 8 };
        bytes[8..8 + prefix_bytes].copy_from_slice(&self.nd_opt_ri_prefix.octets()[..prefix_bytes]);
        
        bytes
    }
}

/// RDNSS option (Type 25)
#[derive(Debug, Clone)]
pub struct RdnssOption {
    pub nd_opt_rdnss_type: u8,
    pub nd_opt_rdnss_len: u8,
    pub nd_opt_rdnss_reserved: u16,
    pub nd_opt_rdnss_lifetime: u32,
    pub nd_opt_rdnss_addresses: Vec<Ipv6Addr>,
}

impl RdnssOption {
    pub fn new(rdnss: &AdvRdnss, _iface: &Interface, cease: bool) -> Self {
        let lifetime = if cease { 0 } else { rdnss.adv_rdnss_lifetime };
        let num_addrs = rdnss.adv_rdnss_addresses.len();
        
        Self {
            nd_opt_rdnss_type: ND_OPT_RDNSS_INFORMATION,
            nd_opt_rdnss_len: (1 + num_addrs * 2) as u8,
            nd_opt_rdnss_reserved: 0,
            nd_opt_rdnss_lifetime: lifetime.to_be(),
            nd_opt_rdnss_addresses: rdnss.adv_rdnss_addresses.clone(),
        }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_len = self.nd_opt_rdnss_len as usize * 8;
        let mut bytes = vec![0u8; total_len];
        bytes[0] = self.nd_opt_rdnss_type;
        bytes[1] = self.nd_opt_rdnss_len;
        // 已经在 new() 中调用 to_be()，这里直接转 bytes
        bytes[2..4].copy_from_slice(&self.nd_opt_rdnss_reserved.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.nd_opt_rdnss_lifetime.to_ne_bytes());
        
        for (i, addr) in self.nd_opt_rdnss_addresses.iter().enumerate() {
            let offset = 8 + i * 16;
            bytes[offset..offset + 16].copy_from_slice(&addr.octets());
        }
        
        bytes
    }
}

/// DNSSL option (Type 31)
#[derive(Debug, Clone)]
pub struct DnsslOption {
    pub nd_opt_dnssl_type: u8,
    pub nd_opt_dnssl_len: u8,
    pub nd_opt_dnssl_reserved: u16,
    pub nd_opt_dnssl_lifetime: u32,
    pub nd_opt_dnssl_domains: Vec<String>,
}

impl DnsslOption {
    pub fn new(dnssl: &AdvDnssl, _iface: &Interface, cease: bool) -> Self {
        let lifetime = if cease { 0 } else { dnssl.adv_dnssl_lifetime };
        
        // Calculate total size needed for domains
        let mut total_bytes = 0usize;
        for domain in &dnssl.adv_dnssl_suffixes {
            total_bytes += domain.len() + 1; // +1 for null terminator
        }
        // Padding to 8-byte boundary
        let padding = (8 - (total_bytes % 8)) % 8;
        total_bytes += padding;
        
        // Length in 8-byte units: header (8 bytes) + domain bytes
        let len = (8 + total_bytes + 7) / 8;
        
        Self {
            nd_opt_dnssl_type: ND_OPT_DNSSL_INFORMATION,
            nd_opt_dnssl_len: len as u8,
            nd_opt_dnssl_reserved: 0,
            nd_opt_dnssl_lifetime: lifetime.to_be(),
            nd_opt_dnssl_domains: dnssl.adv_dnssl_suffixes.clone(),
        }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_len = self.nd_opt_dnssl_len as usize * 8;
        let mut bytes = vec![0u8; total_len];
        bytes[0] = self.nd_opt_dnssl_type;
        bytes[1] = self.nd_opt_dnssl_len;
        // 已经在 new() 中调用 to_be()，这里直接转 bytes
        bytes[2..4].copy_from_slice(&self.nd_opt_dnssl_reserved.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.nd_opt_dnssl_lifetime.to_ne_bytes());
        
        let mut offset = 8;
        for domain in &self.nd_opt_dnssl_domains {
            // Simple encoding - just write the domain string with null terminator
            let domain_bytes = domain.as_bytes();
            bytes[offset..offset + domain_bytes.len()].copy_from_slice(domain_bytes);
            offset += domain_bytes.len() + 1; // +1 for null terminator
        }
        
        bytes
    }
}

/// Mobile IPv6 Advertisement Interval option (Type 7)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AdvIntervalOption {
    pub nd_opt_adv_interval_type: u8,
    pub nd_opt_adv_interval_len: u8,
    pub nd_opt_adv_interval_reserved: u16,
    pub nd_opt_adv_interval_ival: u32,
}

impl AdvIntervalOption {
    pub fn new(interval_ms: u32) -> Self {
        Self {
            nd_opt_adv_interval_type: ND_OPT_RTR_ADV_INTERVAL,
            nd_opt_adv_interval_len: 1,
            nd_opt_adv_interval_reserved: 0,
            nd_opt_adv_interval_ival: interval_ms.to_be(),
        }
    }
    
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.nd_opt_adv_interval_type;
        bytes[1] = self.nd_opt_adv_interval_len;
        // 已经在 new() 中调用 to_be()，这里直接转 bytes
        bytes[2..4].copy_from_slice(&self.nd_opt_adv_interval_reserved.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.nd_opt_adv_interval_ival.to_ne_bytes());
        bytes
    }
}

/// Home Agent Information option (Type 8)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct HomeAgentInfoOption {
    pub nd_opt_hai_type: u8,
    pub nd_opt_hai_len: u8,
    pub nd_opt_hai_flags: u16,
    pub nd_opt_hai_preference: u16,
    pub nd_opt_hai_lifetime: u16,
}

impl HomeAgentInfoOption {
    pub fn new(mipv6: &MobileIpv6, iface: &Interface, cease: bool) -> Self {
        let lifetime = if cease {
            0
        } else if mipv6.home_agent_lifetime >= 0 {
            mipv6.home_agent_lifetime as u16
        } else {
            iface.default_lifetime()
        };
        
        let mut flags = 0u16;
        if mipv6.adv_mob_rtr_support_flag {
            flags |= ND_OPT_HAI_FLAG_SUPPORT_MR_LE;
        }
        
        Self {
            nd_opt_hai_type: ND_OPT_HOME_AGENT_INFO,
            nd_opt_hai_len: 1,
            nd_opt_hai_flags: flags.to_be(),
            nd_opt_hai_preference: mipv6.home_agent_preference.to_be(),
            nd_opt_hai_lifetime: lifetime.to_be(),
        }
    }
    
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.nd_opt_hai_type;
        bytes[1] = self.nd_opt_hai_len;
        // 已经在 new() 中调用 to_be()，这里直接转 bytes
        bytes[2..4].copy_from_slice(&self.nd_opt_hai_flags.to_ne_bytes());
        bytes[4..6].copy_from_slice(&self.nd_opt_hai_preference.to_ne_bytes());
        bytes[6..8].copy_from_slice(&self.nd_opt_hai_lifetime.to_ne_bytes());
        bytes
    }
}

/// Build a complete Router Advertisement packet
/// 选项顺序与 C 代码 radvd 保持一致
pub fn build_ra_packet(iface: &Interface, _dest: Option<&Ipv6Addr>, cease: bool) -> RadvdResult<Vec<u8>> {
    let mut packet = SafeBuffer::with_capacity(MSG_SIZE_SEND);
    
    // Add RA header
    let header = RaHeader::new(iface, cease);
    packet.append(&header.to_bytes());
    
    // 1. Prefix Information (Type 3) - 最先添加
    for prefix in &iface.adv_prefix_list {
        let pi = PrefixInformation::new(prefix, cease);
        packet.append(&pi.to_bytes());
    }
    
    // 2. NAT64 Prefix (if supported)
    // TODO: Add NAT64 prefix support
    
    // 3. Route Information (Type 24)
    for route in &iface.adv_route_list {
        let ri = RouteInfoOption::new(route, iface, cease);
        packet.append(&ri.to_bytes());
    }
    
    // 4. RDNSS (Type 25)
    for rdnss in &iface.adv_rdnss_list {
        let rdnss_opt = RdnssOption::new(rdnss, iface, cease);
        packet.append(&rdnss_opt.to_bytes());
    }
    
    // 5. DNSSL (Type 31)
    for dnssl in &iface.adv_dnssl_list {
        let dnssl_opt = DnsslOption::new(dnssl, iface, cease);
        packet.append(&dnssl_opt.to_bytes());
    }
    
    // 6. MTU (Type 5)
    if iface.adv_link_mtu != 0 {
        let mtu_opt = MtuOption::new(iface.adv_link_mtu);
        packet.append(&mtu_opt.to_bytes());
    }
    
    // 7. SLLAO (Type 1) - 在后面添加，与 C 代码一致
    if iface.adv_source_ll_address && iface.sllao.if_hwaddr_len > 0 {
        let hwaddr = &iface.sllao.if_hwaddr[..iface.sllao.if_hwaddr_len as usize];
        let sllao = SllaoOption::new(hwaddr);
        packet.append(&sllao.to_bytes());
    }
    
    // 8. Mobile IPv6 options
    if iface.mobile_ipv6.adv_interval_opt {
        let interval_ms = (iface.max_rtr_adv_interval * 1000.0) as u32;
        let adv_interval = AdvIntervalOption::new(interval_ms);
        packet.append(&adv_interval.to_bytes());
    }
    
    if iface.mobile_ipv6.adv_home_agent_info {
        let hai = HomeAgentInfoOption::new(&iface.mobile_ipv6, iface, cease);
        packet.append(&hai.to_bytes());
    }
    
    Ok(packet.into_vec())
}

/// Send Router Advertisement to a specific destination or multicast
pub fn send_ra(
    socket: &crate::socket::IcmpV6Socket,
    iface: &Interface,
    dest: Option<&Ipv6Addr>,
) -> RadvdResult<()> {
    let cease = iface.state.cease_adv;
    let packet = build_ra_packet(iface, dest, cease)?;
    
    // Determine destination address
    let dest_addr = if let Some(d) = dest {
        *d
    } else {
        // All-nodes multicast address
        all_nodes_address()
    };
    
    // Get source address (link-local or specified RA source)
    let _src_addr = iface.props.if_addr_rasrc.unwrap_or(iface.props.if_addr);
    
    // Create socket address with interface scope
    let sock_addr = SocketAddrV6::new(dest_addr, 0, 0, iface.props.if_index);
    
    // Send the packet
    socket.send_to(&packet, &sock_addr)?;
    
    Ok(())
}

/// Send RA to all configured clients or multicast
pub fn send_ra_forall(
    socket: &crate::socket::IcmpV6Socket,
    iface: &Interface,
    dest: Option<&Ipv6Addr>,
) -> RadvdResult<()> {
    // Check if interface is ready
    if !iface.state.ready {
        return Ok(());
    }
    
    // Update racount for non-unicast RAs
    if iface.state.racount < MAX_INITIAL_RTR_ADVERTISEMENTS && dest.is_none() {
        // This would need mutable access; caller should handle this
    }
    
    // If no clients configured, send multicast (unless unicast-only)
    if iface.client_list.is_empty() {
        if dest.is_none() && iface.unicast_only {
            return Ok(());
        }
        return send_ra(socket, iface, dest);
    }
    
    // Send to configured clients
    for client in &iface.client_list {
        if dest.is_some() && &client.address != dest.unwrap() {
            continue;
        }
        
        if client.ignored {
            if dest.is_some() {
                return Ok(());
            }
            continue;
        }
        
        send_ra(socket, iface, Some(&client.address))?;
        
        if dest.is_some() {
            return Ok(());
        }
    }
    
    // If we got a direct solicitation from an unlisted client
    if dest.is_some() && iface.unrestricted_unicast {
        return send_ra(socket, iface, dest);
    }
    
    Ok(())
}
