//! Configuration structures for radvd

use crate::constants::*;
use crate::types::*;
use std::net::Ipv6Addr;
use std::time::Duration;

/// Complete radvd configuration
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// List of interfaces to advertise on
    pub interfaces: Vec<Interface>,
}

/// Interface configuration
#[derive(Debug, Clone)]
pub struct Interface {
    /// Ignore if interface is missing at startup
    pub ignore_if_missing: bool,
    /// Send router advertisements
    pub adv_send_advert: bool,
    /// Maximum router advertisement interval (seconds)
    pub max_rtr_adv_interval: f64,
    /// Minimum router advertisement interval (seconds)
    pub min_rtr_adv_interval: f64,
    /// Minimum delay between RAs (seconds)
    pub min_delay_between_ras: f64,
    /// Include source link-layer address
    pub adv_source_ll_address: bool,
    /// Remove advertisements on exit
    pub remove_adv_on_exit: bool,
    /// Unicast only mode
    pub unicast_only: bool,
    /// Unrestricted unicast mode
    pub unrestricted_unicast: bool,
    /// Respond to solicited unicast with unicast RA
    pub adv_ra_solicited_unicast: bool,
    /// Captive Portal API URL
    pub adv_captive_portal_api: Option<String>,
    /// List of allowed clients (None = any client)
    pub client_list: Vec<Client>,

    /// Interface state
    pub state: InterfaceState,
    /// Interface properties
    pub props: InterfaceProperties,
    /// RA header information
    pub ra_header_info: RaHeaderInfo,
    /// Interface timing
    pub times: InterfaceTimes,

    /// Prefix list
    pub adv_prefix_list: Vec<AdvPrefix>,
    /// Route list
    pub adv_route_list: Vec<AdvRoute>,
    /// RDNSS list
    pub adv_rdnss_list: Vec<AdvRdnss>,
    /// DNSSL list
    pub adv_dnssl_list: Vec<AdvDnssl>,
    /// NAT64 prefix list
    pub nat64_prefix_list: Vec<Nat64Prefix>,
    /// Ignore prefix list for autogen
    pub ignore_prefix_list: Vec<AutogenIgnorePrefix>,

    /// Link MTU
    pub adv_link_mtu: u32,
    /// RA MTU
    pub adv_ra_mtu: u32,

    /// Source link-layer address option
    pub sllao: Sllao,

    /// Mobile IPv6 configuration
    pub mobile_ipv6: MobileIpv6,

    /// 6LoWPAN context list
    pub adv_lowpan_co_list: Vec<AdvLowpanCo>,
    /// ABRO list
    pub adv_abro_list: Vec<AdvAbro>,

    /// RA source address list
    pub adv_ra_src_address_list: Vec<RaSrcAddress>,

    /// Line number in config file (for error reporting)
    pub lineno: usize,
}

impl Default for Interface {
    fn default() -> Self {
        let max_interval = DFLT_MAX_RTR_ADV_INTERVAL;
        Self {
            ignore_if_missing: DFLT_IGNORE_IF_MISSING,
            adv_send_advert: DFLT_ADV_SEND_ADVERT,
            max_rtr_adv_interval: max_interval,
            min_rtr_adv_interval: dflt_min_rtr_adv_interval(max_interval),
            min_delay_between_ras: DFLT_MIN_DELAY_BETWEEN_RAS,
            adv_source_ll_address: DFLT_ADV_SOURCE_LL_ADDRESS,
            remove_adv_on_exit: DFLT_REMOVE_ADV_ON_EXIT,
            unicast_only: DFLT_UNICAST_ONLY,
            unrestricted_unicast: DFLT_UNRESTRICTED_UNICAST,
            adv_ra_solicited_unicast: DFLT_ADV_RA_SOLICITED_UNICAST,
            adv_captive_portal_api: None,
            client_list: Vec::new(),
            state: InterfaceState::default(),
            props: InterfaceProperties::default(),
            ra_header_info: RaHeaderInfo::default(),
            times: InterfaceTimes::default(),
            adv_prefix_list: Vec::new(),
            adv_route_list: Vec::new(),
            adv_rdnss_list: Vec::new(),
            adv_dnssl_list: Vec::new(),
            nat64_prefix_list: Vec::new(),
            ignore_prefix_list: Vec::new(),
            adv_link_mtu: DFLT_ADV_LINK_MTU,
            adv_ra_mtu: DFLT_ADV_RA_MTU,
            sllao: Sllao::default(),
            mobile_ipv6: MobileIpv6::default(),
            adv_lowpan_co_list: Vec::new(),
            adv_abro_list: Vec::new(),
            adv_ra_src_address_list: Vec::new(),
            lineno: 0,
        }
    }
}

impl Interface {
    /// Calculate default router lifetime based on max interval
    pub fn default_lifetime(&self) -> u16 {
        if self.ra_header_info.adv_default_lifetime >= 0 {
            self.ra_header_info.adv_default_lifetime as u16
        } else {
            dflt_adv_default_lifetime(self.max_rtr_adv_interval)
        }
    }

    /// Validate interface configuration
    pub fn validate(&self) -> crate::RadvdResult<()> {
        // Validate intervals
        if self.max_rtr_adv_interval < MIN_MAX_RTR_ADV_INTERVAL {
            return Err(crate::RadvdError::config(format!(
                "MaxRtrAdvInterval ({}) must be >= {}",
                self.max_rtr_adv_interval, MIN_MAX_RTR_ADV_INTERVAL
            )));
        }

        if self.max_rtr_adv_interval > MAX_MAX_RTR_ADV_INTERVAL {
            return Err(crate::RadvdError::config(format!(
                "MaxRtrAdvInterval ({}) must be <= {}",
                self.max_rtr_adv_interval, MAX_MAX_RTR_ADV_INTERVAL
            )));
        }

        if self.min_rtr_adv_interval < MIN_MIN_RTR_ADV_INTERVAL {
            return Err(crate::RadvdError::config(format!(
                "MinRtrAdvInterval ({}) must be >= {}",
                self.min_rtr_adv_interval, MIN_MIN_RTR_ADV_INTERVAL
            )));
        }

        let max_min_interval = max_min_rtr_adv_interval(self.max_rtr_adv_interval);
        if self.min_rtr_adv_interval > max_min_interval {
            return Err(crate::RadvdError::config(format!(
                "MinRtrAdvInterval ({}) must be <= {}",
                self.min_rtr_adv_interval, max_min_interval
            )));
        }

        // Validate default lifetime
        let lifetime = self.default_lifetime();
        if lifetime != 0 && lifetime < min_adv_default_lifetime(self.max_rtr_adv_interval) {
            return Err(crate::RadvdError::config(format!(
                "AdvDefaultLifetime ({}) must be 0 or >= {}",
                lifetime,
                min_adv_default_lifetime(self.max_rtr_adv_interval)
            )));
        }

        if lifetime > MAX_ADV_DEFAULT_LIFETIME {
            return Err(crate::RadvdError::config(format!(
                "AdvDefaultLifetime ({}) must be <= {}",
                lifetime, MAX_ADV_DEFAULT_LIFETIME
            )));
        }

        // Validate MTU
        if self.adv_link_mtu != 0
            && (self.adv_link_mtu < MIN_ADV_LINK_MTU || self.adv_link_mtu > MAX_ADV_LINK_MTU)
        {
            return Err(crate::RadvdError::config(format!(
                "AdvLinkMTU ({}) must be 0 or between {} and {}",
                self.adv_link_mtu, MIN_ADV_LINK_MTU, MAX_ADV_LINK_MTU
            )));
        }

        // Validate reachable time
        if self.ra_header_info.adv_reachable_time != 0
            && (self.ra_header_info.adv_reachable_time < MIN_ADV_REACHABLE_TIME
                || self.ra_header_info.adv_reachable_time > MAX_ADV_REACHABLE_TIME)
        {
            return Err(crate::RadvdError::config(format!(
                "AdvReachableTime ({}) must be 0 or between {} and {}",
                self.ra_header_info.adv_reachable_time,
                MIN_ADV_REACHABLE_TIME,
                MAX_ADV_REACHABLE_TIME
            )));
        }

        // Validate retrans timer
        if self.ra_header_info.adv_retrans_timer != 0
            && (self.ra_header_info.adv_retrans_timer < MIN_ADV_RETRANS_TIMER
                || self.ra_header_info.adv_retrans_timer > MAX_ADV_RETRANS_TIMER)
        {
            return Err(crate::RadvdError::config(format!(
                "AdvRetransTimer ({}) must be 0 or between {} and {}",
                self.ra_header_info.adv_retrans_timer,
                MIN_ADV_RETRANS_TIMER,
                MAX_ADV_RETRANS_TIMER
            )));
        }

        // Validate cur hop limit
        if self.ra_header_info.adv_cur_hop_limit != 0
            && (self.ra_header_info.adv_cur_hop_limit < MIN_ADV_CUR_HOP_LIMIT
                || self.ra_header_info.adv_cur_hop_limit > MAX_ADV_CUR_HOP_LIMIT)
        {
            return Err(crate::RadvdError::config(format!(
                "AdvCurHopLimit ({}) must be 0 or between {} and {}",
                self.ra_header_info.adv_cur_hop_limit,
                MIN_ADV_CUR_HOP_LIMIT,
                MAX_ADV_CUR_HOP_LIMIT
            )));
        }

        Ok(())
    }
}

/// Prefix advertisement configuration
#[derive(Debug, Clone)]
pub struct AdvPrefix {
    /// Prefix address
    pub prefix: Ipv6Addr,
    /// Prefix length
    pub prefix_len: u8,

    /// On-link flag
    pub adv_on_link_flag: bool,
    /// Autonomous flag
    pub adv_autonomous_flag: bool,
    /// Valid lifetime (seconds)
    pub adv_valid_lifetime: u32,
    /// Preferred lifetime (seconds)
    pub adv_preferred_lifetime: u32,
    /// Deprecate prefix flag
    pub deprecate_prefix_flag: bool,
    /// Decrement lifetimes flag
    pub decrement_lifetimes_flag: bool,

    /// Current valid lifetime (for decrement mode)
    pub curr_validlft: u32,
    /// Current preferred lifetime (for decrement mode)
    pub curr_preferredlft: u32,

    /// Router address flag (Mobile IPv6)
    pub adv_router_addr: bool,

    /// 6to4 interface name
    pub if6to4: Option<String>,
    /// Interface to select prefixes from
    pub if6: Option<String>,
}

impl Default for AdvPrefix {
    fn default() -> Self {
        Self {
            prefix: Ipv6Addr::UNSPECIFIED,
            prefix_len: 64,
            adv_on_link_flag: DFLT_ADV_ON_LINK_FLAG,
            adv_autonomous_flag: DFLT_ADV_AUTONOMOUS_FLAG,
            adv_valid_lifetime: DFLT_ADV_VALID_LIFETIME,
            adv_preferred_lifetime: DFLT_ADV_PREFERRED_LIFETIME,
            deprecate_prefix_flag: DFLT_DEPRECATE_PREFIX_FLAG,
            decrement_lifetimes_flag: DFLT_DECREMENT_LIFETIMES_FLAG,
            curr_validlft: 0,
            curr_preferredlft: 0,
            adv_router_addr: DFLT_ADV_ROUTER_ADDR,
            if6to4: None,
            if6: None,
        }
    }
}

impl AdvPrefix {
    /// Get effective valid lifetime
    pub fn effective_valid_lifetime(&self, cease: bool) -> u32 {
        if cease {
            0
        } else if self.decrement_lifetimes_flag && self.curr_validlft > 0 {
            self.curr_validlft
        } else {
            self.adv_valid_lifetime
        }
    }

    /// Get effective preferred lifetime
    pub fn effective_preferred_lifetime(&self, cease: bool) -> u32 {
        if cease {
            0
        } else if self.decrement_lifetimes_flag && self.curr_preferredlft > 0 {
            self.curr_preferredlft
        } else {
            self.adv_preferred_lifetime
        }
    }

    /// Validate prefix configuration
    pub fn validate(&self) -> crate::RadvdResult<()> {
        if self.prefix_len > MAX_PREFIX_LEN {
            return Err(crate::RadvdError::config(format!(
                "Prefix length ({}) must be <= {}",
                self.prefix_len, MAX_PREFIX_LEN
            )));
        }

        // Preferred lifetime must not exceed valid lifetime
        if self.adv_preferred_lifetime > self.adv_valid_lifetime {
            return Err(crate::RadvdError::config(
                "AdvPreferredLifetime must not exceed AdvValidLifetime",
            ));
        }

        // Check minimum valid lifetime for SLAAC (RFC 4862)
        if self.adv_autonomous_flag && self.adv_valid_lifetime < MIN_ADV_VALID_LIFETIME {
            return Err(crate::RadvdError::config(format!(
                "AdvValidLifetime ({}) must be >= {} for autonomous prefixes",
                self.adv_valid_lifetime, MIN_ADV_VALID_LIFETIME
            )));
        }

        Ok(())
    }
}

/// Route advertisement configuration
#[derive(Debug, Clone)]
pub struct AdvRoute {
    /// Route prefix
    pub prefix: Ipv6Addr,
    /// Prefix length
    pub prefix_len: u8,

    /// Route preference
    pub adv_route_preference: RouterPreference,
    /// Route lifetime (seconds)
    pub adv_route_lifetime: u32,
    /// Remove route flag
    pub remove_route_flag: bool,
}

impl Default for AdvRoute {
    fn default() -> Self {
        Self {
            prefix: Ipv6Addr::UNSPECIFIED,
            prefix_len: 64,
            adv_route_preference: RouterPreference::Medium,
            adv_route_lifetime: 0, // Will be set based on MaxRtrAdvInterval
            remove_route_flag: DFLT_REMOVE_ROUTE_FLAG,
        }
    }
}

impl AdvRoute {
    /// Set default lifetime based on MaxRtrAdvInterval
    pub fn set_default_lifetime(&mut self, max_rtr_adv_interval: f64) {
        if self.adv_route_lifetime == 0 {
            self.adv_route_lifetime = dflt_adv_route_lifetime(max_rtr_adv_interval);
        }
    }
}

/// RDNSS (Recursive DNS Server) configuration
#[derive(Debug, Clone)]
pub struct AdvRdnss {
    /// Number of addresses
    pub adv_rdnss_number: usize,
    /// Lifetime (seconds)
    pub adv_rdnss_lifetime: u32,
    /// Flush RDNSS flag
    pub flush_rdnss_flag: bool,
    /// DNS server addresses
    pub adv_rdnss_addresses: Vec<Ipv6Addr>,
}

impl Default for AdvRdnss {
    fn default() -> Self {
        Self {
            adv_rdnss_number: 0,
            adv_rdnss_lifetime: 0, // Will be set based on MaxRtrAdvInterval
            flush_rdnss_flag: DFLT_FLUSH_RDNSS_FLAG,
            adv_rdnss_addresses: Vec::new(),
        }
    }
}

impl AdvRdnss {
    /// Set default lifetime based on MaxRtrAdvInterval
    pub fn set_default_lifetime(&mut self, max_rtr_adv_interval: f64) {
        if self.adv_rdnss_lifetime == 0 {
            self.adv_rdnss_lifetime = dflt_adv_rdnss_lifetime(max_rtr_adv_interval) as u32;
        }
    }

    /// Check if address is in the list
    pub fn contains(&self, addr: &Ipv6Addr) -> bool {
        self.adv_rdnss_addresses.contains(addr)
    }
}

/// DNSSL (DNS Search List) configuration
#[derive(Debug, Clone)]
pub struct AdvDnssl {
    /// Lifetime (seconds)
    pub adv_dnssl_lifetime: u32,
    /// Number of suffixes
    pub adv_dnssl_number: usize,
    /// Flush DNSSL flag
    pub flush_dnssl_flag: bool,
    /// DNS search suffixes
    pub adv_dnssl_suffixes: Vec<String>,
}

impl Default for AdvDnssl {
    fn default() -> Self {
        Self {
            adv_dnssl_lifetime: 0, // Will be set based on MaxRtrAdvInterval
            adv_dnssl_number: 0,
            flush_dnssl_flag: DFLT_FLUSH_DNSSL_FLAG,
            adv_dnssl_suffixes: Vec::new(),
        }
    }
}

impl AdvDnssl {
    /// Set default lifetime based on MaxRtrAdvInterval
    pub fn set_default_lifetime(&mut self, max_rtr_adv_interval: f64) {
        if self.adv_dnssl_lifetime == 0 {
            self.adv_dnssl_lifetime = dflt_adv_dnssl_lifetime(max_rtr_adv_interval) as u32;
        }
    }

    /// Check if suffix is in the list
    pub fn contains(&self, suffix: &str) -> bool {
        self.adv_dnssl_suffixes.iter().any(|s| s == suffix)
    }
}

/// 6LoWPAN Context Option configuration
#[derive(Debug, Clone)]
pub struct AdvLowpanCo {
    /// Context length
    pub context_length: u8,
    /// Context compression flag
    pub context_compression_flag: u8,
    /// Context ID
    pub adv_context_id: u8,
    /// Lifetime
    pub adv_life_time: u16,
    /// Context prefix
    pub adv_context_prefix: Ipv6Addr,
}

/// ABRO (Authoritative Border Router Option) configuration
#[derive(Debug, Clone)]
pub struct AdvAbro {
    /// Version (low and high)
    pub version: [u16; 2],
    /// Valid lifetime
    pub valid_life_time: u16,
    /// 6LBR address
    pub lbr_address: Ipv6Addr,
}
