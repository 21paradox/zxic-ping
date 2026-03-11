//! Protocol constants and default values for radvd
//!
//! These constants are based on RFC 4861 (Neighbor Discovery for IPv6),
//! RFC 4862 (IPv6 Stateless Address Autoconfiguration), and related standards.

use std::time::Duration;

/// Maximum message size for incoming and outgoing RSs and RAs
pub const MSG_SIZE_RECV: usize = 1500;
pub const MSG_SIZE_SEND: usize = 1452;

/// RFC 2460 minimum MTU - lowest valid MTU supported by IPv6
pub const RFC2460_MIN_MTU: u32 = 1280;

/// Hardware address maximum length
pub const HWADDR_MAX: usize = 16;

/// User HZ for timer calculations
pub const USER_HZ: u64 = 100;

// ============================================================================
// Router Configuration Variables - Default Values
// ============================================================================

/// Default: Ignore interface if missing at startup
pub const DFLT_IGNORE_IF_MISSING: bool = true;

/// Default: Send router advertisements
pub const DFLT_ADV_SEND_ADVERT: bool = false;

/// Default: Maximum router advertisement interval (seconds)
pub const DFLT_MAX_RTR_ADV_INTERVAL: f64 = 600.0;

/// Default: Minimum router advertisement interval (calculated as 0.33 * MaxRtrAdvInterval)
pub fn dflt_min_rtr_adv_interval(max_interval: f64) -> f64 {
    0.33 * max_interval
}

/// Default: Managed address configuration flag
pub const DFLT_ADV_MANAGED_FLAG: bool = false;

/// Default: Other stateful configuration flag
pub const DFLT_ADV_OTHER_CONFIG_FLAG: bool = false;

/// Default: Link MTU (0 means unspecified)
pub const DFLT_ADV_LINK_MTU: u32 = 0;

/// Default: Reachable time (milliseconds, 0 means unspecified)
pub const DFLT_ADV_REACHABLE_TIME: u32 = 0;

/// Default: Retransmit timer (milliseconds, 0 means unspecified)
pub const DFLT_ADV_RETRANS_TIMER: u32 = 0;

/// Default: Current hop limit (as per RFC 1700)
pub const DFLT_ADV_CUR_HOP_LIMIT: u8 = 64;

/// Default: Default router lifetime (seconds)
pub fn dflt_adv_default_lifetime(max_interval: f64) -> u16 {
    let calculated = (3.0 * max_interval) as u16;
    calculated.max(1)
}

/// Default: Minimum delay between RAs
pub const DFLT_MIN_DELAY_BETWEEN_RAS: f64 = MIN_DELAY_BETWEEN_RAS;

/// Default: Default router preference
pub const DFLT_ADV_DEFAULT_PREFERENCE: i32 = 0;

/// Default: RA MTU
pub const DFLT_ADV_RA_MTU: u32 = RFC2460_MIN_MTU;

/// Default: Unicast only mode
pub const DFLT_UNICAST_ONLY: bool = false;

/// Default: Unrestricted unicast mode
pub const DFLT_UNRESTRICTED_UNICAST: bool = false;

/// Default: Respond to solicited unicast RS with unicast RA
pub const DFLT_ADV_RA_SOLICITED_UNICAST: bool = true;

/// Default: Remove advertisements on exit
pub const DFLT_REMOVE_ADV_ON_EXIT: bool = true;

// ============================================================================
// Prefix Default Values
// ============================================================================

/// Default: Include source link-layer address in RA
pub const DFLT_ADV_SOURCE_LL_ADDRESS: bool = true;

/// Default: Valid lifetime for prefixes (seconds) - 1 day
pub const DFLT_ADV_VALID_LIFETIME: u32 = 86400;

/// Default: On-link flag for prefixes
pub const DFLT_ADV_ON_LINK_FLAG: bool = true;

/// Default: Preferred lifetime for prefixes (seconds) - 4 hours
pub const DFLT_ADV_PREFERRED_LIFETIME: u32 = 14400;

/// Default: Autonomous flag for prefixes
pub const DFLT_ADV_AUTONOMOUS_FLAG: bool = true;

/// Default: Deprecate prefix flag
pub const DFLT_DEPRECATE_PREFIX_FLAG: bool = false;

/// Default: Decrement lifetimes flag
pub const DFLT_DECREMENT_LIFETIMES_FLAG: bool = false;

// ============================================================================
// NAT64 Default Values (RFC 8781)
// ============================================================================

/// Default: NAT64 maximum valid lifetime (non-scaled value 8191 << 3 = 65528)
pub const DFLT_NAT64_MAX_VALID_LIFETIME: u32 = 65528;

// ============================================================================
// Route Default Values
// ============================================================================

/// Default: Route lifetime (seconds)
pub fn dflt_adv_route_lifetime(max_interval: f64) -> u32 {
    (3.0 * max_interval) as u32
}

/// Default: Route preference
pub const DFLT_ADV_ROUTE_PREFERENCE: i32 = 0; // medium

/// Default: Remove route flag
pub const DFLT_REMOVE_ROUTE_FLAG: bool = true;

// ============================================================================
// RDNSS Default Values (RFC 8106)
// ============================================================================

/// Default: RDNSS lifetime (seconds) - "SHOULD be at least 3 * MaxRtrAdvInterval"
pub fn dflt_adv_rdnss_lifetime(max_interval: f64) -> f64 {
    3.0 * max_interval
}

/// Default: Flush RDNSS flag
pub const DFLT_FLUSH_RDNSS_FLAG: bool = true;

// ============================================================================
// DNSSL Default Values (RFC 8106)
// ============================================================================

/// Default: DNSSL lifetime (seconds) - "SHOULD be at least 3 * MaxRtrAdvInterval"
pub fn dflt_adv_dnssl_lifetime(max_interval: f64) -> f64 {
    3.0 * max_interval
}

/// Default: Flush DNSSL flag
pub const DFLT_FLUSH_DNSSL_FLAG: bool = true;

// ============================================================================
// Protocol Constants (RFC 4861)
// ============================================================================

/// Maximum initial router advertisement interval (seconds)
pub const MAX_INITIAL_RTR_ADV_INTERVAL: u16 = 16;

/// Maximum initial router advertisements
pub const MAX_INITIAL_RTR_ADVERTISEMENTS: u32 = 3;

/// Maximum final router advertisements
pub const MAX_FINAL_RTR_ADVERTISEMENTS: u32 = 3;

/// Minimum delay between RAs (seconds)
pub const MIN_DELAY_BETWEEN_RAS: f64 = 3.0;

/// Minimum delay between RAs for MIPv6 (seconds)
pub const MIN_DELAY_BETWEEN_RAS_MIPV6: f64 = 30.0 / 1000.0;

/// Maximum RA delay (seconds)
pub const MAX_RA_DELAY_SECONDS: f64 = 0.5;

// ============================================================================
// Host Constants (RFC 4861)
// ============================================================================

/// Maximum router solicitation delay (seconds)
pub const MAX_RTR_SOLICITATION_DELAY: u8 = 1;

/// Router solicitation interval (seconds)
pub const RTR_SOLICITATION_INTERVAL: u8 = 4;

/// Maximum router solicitations
pub const MAX_RTR_SOLICITATIONS: u8 = 3;

// ============================================================================
// Node Constants (RFC 4861)
// ============================================================================

pub const MAX_MULTICAST_SOLICIT: u8 = 3;
pub const MAX_UNICAST_SOLICIT: u8 = 3;
pub const MAX_ANYCAST_DELAY_TIME: u8 = 1;
pub const MAX_NEIGHBOR_ADVERTISEMENT: u8 = 3;
pub const REACHABLE_TIME: u32 = 30000; // milliseconds
pub const RETRANS_TIMER: u32 = 1000; // milliseconds
pub const DELAY_FIRST_PROBE_TIME: u8 = 5;
pub const MIN_RANDOM_FACTOR: f64 = 0.5; // 1.0 / 2.0
pub const MAX_RANDOM_FACTOR: f64 = 1.5; // 3.0 / 2.0

// ============================================================================
// MIN/MAX Values (RFC 4861 and RFC 8316)
// ============================================================================

pub const MIN_MAX_RTR_ADV_INTERVAL: f64 = 4.0;
pub const MAX_MAX_RTR_ADV_INTERVAL: f64 = 65535.0;

pub const MIN_MIN_RTR_ADV_INTERVAL: f64 = 3.0;

pub fn max_min_rtr_adv_interval(max_interval: f64) -> f64 {
    0.75 * max_interval
}

pub fn min_adv_default_lifetime(max_interval: f64) -> u16 {
    ((max_interval as u16).max(1)).max(max_interval as u16)
}

pub const MAX_ADV_DEFAULT_LIFETIME: u16 = 65535;

pub const MIN_ADV_LINK_MTU: u32 = RFC2460_MIN_MTU;
pub const MAX_ADV_LINK_MTU: u32 = 131_072;

pub const MIN_ADV_RA_MTU: u32 = MIN_ADV_LINK_MTU;
pub const MAX_ADV_RA_MTU: u32 = MAX_ADV_LINK_MTU;

pub const MIN_ADV_REACHABLE_TIME: u32 = 100;
pub const MAX_ADV_REACHABLE_TIME: u32 = 3_600_000; // 1 hour in milliseconds

pub const MIN_ADV_RETRANS_TIMER: u32 = 10;
pub const MAX_ADV_RETRANS_TIMER: u32 = 3_600_000;

pub const MIN_ADV_CUR_HOP_LIMIT: u8 = 2;
pub const MAX_ADV_CUR_HOP_LIMIT: u8 = 255;

pub const MAX_PREFIX_LEN: u8 = 128;

// ============================================================================
// SLAAC Constants (RFC 4862)
// ============================================================================

/// Minimum valid lifetime (2 hours in seconds)
pub const MIN_ADV_VALID_LIFETIME: u32 = 7200;

// ============================================================================
// Mobile IPv6 Extensions
// ============================================================================

pub const DFLT_ADV_ROUTER_ADDR: bool = false;
pub const DFLT_ADV_HOME_AGENT_FLAG: bool = false;
pub const DFLT_ADV_INTERVAL_OPT: bool = false;
pub const DFLT_ADV_HOME_AGENT_INFO: bool = false;

// Option types
pub const ND_OPT_RTR_ADV_INTERVAL: u8 = 7;
pub const ND_OPT_HOME_AGENT_INFO: u8 = 8;
pub const ND_OPT_ROUTE_INFORMATION: u8 = 24;
pub const ND_OPT_RDNSS_INFORMATION: u8 = 25;
pub const ND_OPT_DNSSL_INFORMATION: u8 = 31;
pub const ND_OPT_CAPTIVE_PORTAL: u8 = 37;
pub const ND_OPT_PREF64: u8 = 38;

// ARO, 6CO, ABRO for 6LoWPAN
pub const ND_OPT_ARO: u8 = 33;
pub const ND_OPT_6CO: u8 = 34;
pub const ND_OPT_ABRO: u8 = 35;

// ND Option Timestamp
pub const ND_OPT_TIMESTAMP: u8 = 13;

// ============================================================================
// NEMO Extensions
// ============================================================================

pub const DFLT_ADV_MOB_RTR_SUPPORT_FLAG: bool = false;

// ============================================================================
// Flags
// ============================================================================

/// ND Router Advertisement flag: Home Agent
pub const ND_RA_FLAG_HOME_AGENT: u8 = 0x20;

/// ND Prefix Information flag: Router Address
pub const ND_OPT_PI_FLAG_RADDR: u8 = 0x20;

/// Route Information preference shift
pub const ND_OPT_RI_PRF_SHIFT: u8 = 3;
pub const ND_OPT_RI_PRF_MASK: u8 = 0x18; // 00011000

/// RDNSS flag S (SLAAC) - little endian
pub const ND_OPT_RDNSSI_FLAG_S_LE: u16 = 0x0008;
/// RDNSS flag S (SLAAC) - big endian
pub const ND_OPT_RDNSSI_FLAG_S_BE: u16 = 0x0800;

/// Home Agent Info flag: Support Mobile Router (little endian)
pub const ND_OPT_HAI_FLAG_SUPPORT_MR_LE: u16 = 0x0080;
/// Home Agent Info flag: Support Mobile Router (big endian)
pub const ND_OPT_HAI_FLAG_SUPPORT_MR_BE: u16 = 0x8000;

// ============================================================================
// Mobile IPv6 Timing Constants
// ============================================================================

pub const MIN_MIN_RTR_ADV_INTERVAL_MIPV6: f64 = 3.0 / 100.0;
pub const MIN_MAX_RTR_ADV_INTERVAL_MIPV6: f64 = 7.0 / 100.0;
pub const RTR_SOLICITATION_INTERVAL_MIPV6: u8 = 1;

pub const CAUTIOUS_MAX_RTR_ADV_INTERVAL: f64 = 2.0 / 10.0;
pub const CAUTIOUS_MAX_RTR_ADV_INTERVAL_LEEWAY: f64 = 2.0 / 100.0;

pub const MIN_HOME_AGENT_LIFETIME: u16 = 1; // 0 must NOT be used
pub const MAX_HOME_AGENT_LIFETIME: u16 = 65520; // 18.2 hours in secs

// ============================================================================
// Other Default Values
// ============================================================================

pub const DFLT_HOME_AGENT_PREFERENCE: u16 = 0;

pub fn dflt_home_agent_lifetime(default_lifetime: u16) -> u16 {
    default_lifetime
}
