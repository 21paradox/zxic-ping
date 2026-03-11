//! Type definitions for radvd

use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime};

/// Hardware address (MAC address)
pub type HwAddr = [u8; crate::constants::HWADDR_MAX];

/// Router preference levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouterPreference {
    #[default]
    Medium = 0,
    High = 1,
    Low = 3,
}

impl RouterPreference {
    pub fn from_i32(value: i32) -> Self {
        match value {
            1 => RouterPreference::High,
            3 => RouterPreference::Low,
            _ => RouterPreference::Medium,
        }
    }

    pub fn as_i32(self) -> i32 {
        self as i32
    }

    pub fn as_u8_for_ra(self) -> u8 {
        // For RA header: preference is encoded in bits 3-4 of flags field
        ((self as u8) << 3) & 0x18
    }
}

impl std::str::FromStr for RouterPreference {
    type Err = crate::RadvdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(RouterPreference::Low),
            "medium" => Ok(RouterPreference::Medium),
            "high" => Ok(RouterPreference::High),
            _ => Err(crate::RadvdError::config(format!(
                "Invalid router preference: {}",
                s
            ))),
        }
    }
}

/// Interface state information
#[derive(Debug, Clone, Default)]
pub struct InterfaceState {
    /// Interface has been initialized successfully
    pub ready: bool,
    /// Interface settings have changed
    pub changed: bool,
    /// Should cease sending advertisements
    pub cease_adv: bool,
    /// Count of non-unicast initial router advertisements
    pub racount: u32,
}

/// Interface properties
#[derive(Debug, Clone)]
pub struct InterfaceProperties {
    /// Interface name
    pub name: String,
    /// Interface index
    pub if_index: u32,
    /// First link-local address
    pub if_addr: Ipv6Addr,
    /// All addresses
    pub if_addrs: Vec<Ipv6Addr>,
    /// Selected AdvRASrcAddress or None
    pub if_addr_rasrc: Option<Ipv6Addr>,
    /// Maximum RA option size
    pub max_ra_option_size: u32,
}

impl Default for InterfaceProperties {
    fn default() -> Self {
        Self {
            name: String::new(),
            if_index: 0,
            if_addr: Ipv6Addr::UNSPECIFIED,
            if_addrs: Vec::new(),
            if_addr_rasrc: None,
            max_ra_option_size: 0,
        }
    }
}

/// Router Advertisement header information
#[derive(Debug, Clone)]
pub struct RaHeaderInfo {
    /// Managed address configuration flag
    pub adv_managed_flag: bool,
    /// Other stateful configuration flag
    pub adv_other_config_flag: bool,
    /// Current hop limit
    pub adv_cur_hop_limit: u8,
    /// Home agent flag
    pub adv_home_agent_flag: bool,
    /// Default lifetime (use -1 for special handling)
    pub adv_default_lifetime: i32,
    /// Default preference
    pub adv_default_preference: RouterPreference,
    /// Reachable time (milliseconds)
    pub adv_reachable_time: u32,
    /// Retransmit timer (milliseconds)
    pub adv_retrans_timer: u32,
}

impl Default for RaHeaderInfo {
    fn default() -> Self {
        use crate::constants::DFLT_ADV_CUR_HOP_LIMIT;
        Self {
            adv_managed_flag: false,
            adv_other_config_flag: false,
            adv_cur_hop_limit: DFLT_ADV_CUR_HOP_LIMIT,
            adv_home_agent_flag: false,
            adv_default_lifetime: -1, // Will be calculated
            adv_default_preference: RouterPreference::Medium,
            adv_reachable_time: 0,
            adv_retrans_timer: 0,
        }
    }
}

/// Interface timing information
#[derive(Debug, Clone, Default)]
pub struct InterfaceTimes {
    /// Last multicast RA sent
    pub last_multicast: Option<SystemTime>,
    /// Next scheduled multicast RA
    pub next_multicast: Option<SystemTime>,
    /// Last RA time (any type)
    pub last_ra_time: Option<SystemTime>,
}

/// Source Link-Layer Address Option
#[derive(Debug, Clone, Default)]
pub struct Sllao {
    /// Hardware address
    pub if_hwaddr: HwAddr,
    /// Hardware address length
    pub if_hwaddr_len: i32,
    /// Prefix length
    pub if_prefix_len: i32,
    /// Maximum MTU
    pub if_maxmtu: i32,
}

/// Mobile IPv6 configuration
#[derive(Debug, Clone, Default)]
pub struct MobileIpv6 {
    /// Advertise interval option
    pub adv_interval_opt: bool,
    /// Advertise home agent info
    pub adv_home_agent_info: bool,
    /// Home agent preference
    pub home_agent_preference: u16,
    /// Home agent lifetime (use -1 for default)
    pub home_agent_lifetime: i32,
    /// Mobile router support flag (NEMO)
    pub adv_mob_rtr_support_flag: bool,
}

/// NAT64 prefix
#[derive(Debug, Clone)]
pub struct Nat64Prefix {
    /// Prefix address
    pub prefix: Ipv6Addr,
    /// Prefix length
    pub prefix_len: u8,
    /// Valid lifetime
    pub adv_valid_lifetime: u32,
    /// Current valid lifetime
    pub curr_validlft: u32,
    /// Next prefix in list
    pub next: Option<Box<Nat64Prefix>>,
}

/// Prefix to ignore for autogen
#[derive(Debug, Clone)]
pub struct AutogenIgnorePrefix {
    /// Prefix address
    pub prefix: Ipv6Addr,
    /// Prefix mask
    pub mask: Ipv6Addr,
    /// Next in list
    pub next: Option<Box<AutogenIgnorePrefix>>,
}

/// Client entry
#[derive(Debug, Clone)]
pub struct Client {
    /// Client IPv6 address
    pub address: Ipv6Addr,
    /// Should be ignored
    pub ignored: bool,
}

/// RA Source address entry
#[derive(Debug, Clone)]
pub struct RaSrcAddress {
    /// Source address
    pub address: Ipv6Addr,
}

/// Safe buffer for building packets
#[derive(Debug)]
pub struct SafeBuffer {
    buffer: Vec<u8>,
}

impl SafeBuffer {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(crate::constants::MSG_SIZE_SEND),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    pub fn append(&mut self, data: &[u8]) -> usize {
        self.buffer.extend_from_slice(data);
        data.len()
    }

    pub fn pad(&mut self, count: usize) -> usize {
        self.buffer.resize(self.buffer.len() + count, 0);
        count
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buffer
    }
}

impl Default for SafeBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Buffer for building RA options (may need multiple buffers for large configs)
#[derive(Debug)]
pub struct SafeBufferList {
    buffers: Vec<SafeBuffer>,
}

impl SafeBufferList {
    pub fn new() -> Self {
        Self { buffers: Vec::new() }
    }

    pub fn append(&mut self) -> &mut SafeBuffer {
        self.buffers.push(SafeBuffer::new());
        self.buffers.last_mut().unwrap()
    }

    pub fn to_buffer(self) -> SafeBuffer {
        let total_len: usize = self.buffers.iter().map(|b| b.len()).sum();
        let mut result = SafeBuffer::with_capacity(total_len);
        for buf in self.buffers {
            result.append(buf.as_slice());
        }
        result
    }

    pub fn iter(&self) -> impl Iterator<Item = &SafeBuffer> {
        self.buffers.iter()
    }
}

impl Default for SafeBufferList {
    fn default() -> Self {
        Self::new()
    }
}
