//! Configuration file parser for radvd
//!
//! This is a simplified parser for radvd.conf files.
//! A full implementation would use nom or a similar parser combinator library.

use crate::config::*;
use crate::constants::*;
use crate::error::{RadvdError, RadvdResult};
use crate::types::*;
use crate::util::parse_prefix;
use std::net::Ipv6Addr;

/// Parse a radvd configuration file
pub fn parse_config(content: &str) -> RadvdResult<Config> {
    let mut config = Config::default();
    let mut current_iface: Option<Interface> = None;
    let mut current_prefix: Option<AdvPrefix> = None;
    let mut current_route: Option<AdvRoute> = None;
    let mut current_rdnss: Option<AdvRdnss> = None;
    let mut current_dnssl: Option<AdvDnssl> = None;
    let mut current_depth = 0; // Track nesting depth
    
    for (line_no, orig_line) in content.lines().enumerate() {
        let mut line = orig_line.trim().to_string();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Check for interface definition BEFORE handling braces
        // Interface definitions have the format: "interface name {"
        let is_interface_def = line.to_lowercase().starts_with("interface ");
        
        if is_interface_def && current_depth == 0 {
            // Save previous interface if any
            if let Some(iface) = current_iface.take() {
                config.interfaces.push(iface);
            }
        }
        
        // Handle braces
        let open_braces = line.matches('{').count();
        let close_braces = line.matches('}').count();
        
        // Handle closing braces FIRST (before opening)
        if close_braces > 0 {
            current_depth -= close_braces;
            
            // Pop current context based on depth
            if current_depth == 1 {
                if let Some(ref mut iface) = current_iface {
                    if let Some(prefix) = current_prefix.take() {
                        iface.adv_prefix_list.push(prefix);
                    } else if let Some(route) = current_route.take() {
                        iface.adv_route_list.push(route);
                    } else if let Some(rdnss) = current_rdnss.take() {
                        let mut rdnss = rdnss;
                        rdnss.adv_rdnss_number = rdnss.adv_rdnss_addresses.len();
                        iface.adv_rdnss_list.push(rdnss);
                    } else if let Some(dnssl) = current_dnssl.take() {
                        let mut dnssl = dnssl;
                        dnssl.adv_dnssl_number = dnssl.adv_dnssl_suffixes.len();
                        iface.adv_dnssl_list.push(dnssl);
                    }
                }
            } else if current_depth <= 0 {
                if let Some(iface) = current_iface.take() {
                    config.interfaces.push(iface);
                }
            }
            
            if line.starts_with("};") || line.starts_with("}") {
                continue;
            }
            
            // Remove closing brace syntax for token parsing
            line = line.replace("};", "").replace("}", "").trim().to_string();
        }
        
        // Handle opening braces
        if open_braces > 0 {
            current_depth += open_braces;
            // Remove braces for token parsing
            line = line.replace('{', "").trim().to_string();
            if line.is_empty() {
                continue;
            }
        }
        
        // Parse tokens (remove trailing semicolons)
        let tokens: Vec<String> = line
            .split_whitespace()
            .map(|t| t.trim_end_matches(';').to_string())
            .filter(|t| !t.is_empty())
            .collect();
        if tokens.is_empty() {
            continue;
        }
        
        let keyword = tokens[0].to_lowercase();
        
        // Interface definition (already handled depth check above)
        if keyword == "interface" {
            
            if tokens.len() < 2 {
                return Err(RadvdError::parse(format!(
                    "Line {}: interface missing name",
                    line_no + 1
                )));
            }
            let mut iface = Interface::default();
            iface.props.name = tokens[1].to_string();
            iface.lineno = line_no + 1;
            current_iface = Some(iface);
            continue;
        }
        
        // Inside interface block
        if let Some(ref mut iface) = current_iface {
            match keyword.as_str() {
                // Interface-level options
                "ignoreifmissing" => {
                    iface.ignore_if_missing = parse_bool(&tokens)?;
                }
                "advsendadvert" => {
                    iface.adv_send_advert = parse_bool(&tokens)?;
                }
                "maxrtradvinterval" => {
                    iface.max_rtr_adv_interval = parse_f64(&tokens, line_no + 1)?;
                    // Recalculate min interval
                    iface.min_rtr_adv_interval = dflt_min_rtr_adv_interval(iface.max_rtr_adv_interval);
                }
                "minrtradvinterval" => {
                    iface.min_rtr_adv_interval = parse_f64(&tokens, line_no + 1)?;
                }
                "mindelaybetweenras" => {
                    iface.min_delay_between_ras = parse_f64(&tokens, line_no + 1)?;
                }
                "advmanagedflag" => {
                    iface.ra_header_info.adv_managed_flag = parse_bool(&tokens)?;
                }
                "advotherconfigflag" => {
                    iface.ra_header_info.adv_other_config_flag = parse_bool(&tokens)?;
                }
                "advlinkmtu" => {
                    iface.adv_link_mtu = parse_u32(&tokens, line_no + 1)?;
                }
                "advramtu" => {
                    iface.adv_ra_mtu = parse_u32(&tokens, line_no + 1)?;
                }
                "advreachabletime" => {
                    iface.ra_header_info.adv_reachable_time = parse_u32(&tokens, line_no + 1)?;
                }
                "advretranstimer" => {
                    iface.ra_header_info.adv_retrans_timer = parse_u32(&tokens, line_no + 1)?;
                }
                "advcurhoplimit" => {
                    iface.ra_header_info.adv_cur_hop_limit = parse_u8(&tokens, line_no + 1)?;
                }
                "advdefaultlifetime" => {
                    iface.ra_header_info.adv_default_lifetime = parse_i32(&tokens, line_no + 1)?;
                }
                "advdefaultpreference" => {
                    let pref = parse_string(&tokens, line_no + 1)?.to_lowercase();
                    iface.ra_header_info.adv_default_preference = match pref.as_str() {
                        "low" => RouterPreference::Low,
                        "medium" => RouterPreference::Medium,
                        "high" => RouterPreference::High,
                        _ => return Err(RadvdError::parse(format!(
                            "Line {}: invalid preference {}",
                            line_no + 1, pref
                        ))),
                    };
                }
                "advsourcelladdress" => {
                    iface.adv_source_ll_address = parse_bool(&tokens)?;
                }
                "removeadvonexit" => {
                    iface.remove_adv_on_exit = parse_bool(&tokens)?;
                }
                "unicastonly" => {
                    iface.unicast_only = parse_bool(&tokens)?;
                }
                "unrestrictedunicast" => {
                    iface.unrestricted_unicast = parse_bool(&tokens)?;
                }
                "advrasolicitedunicast" => {
                    iface.adv_ra_solicited_unicast = parse_bool(&tokens)?;
                }
                "advcaptiveportalapi" => {
                    iface.adv_captive_portal_api = Some(parse_string(&tokens, line_no + 1)?.trim_matches('"').to_string());
                }
                "advhomeagentflag" => {
                    iface.ra_header_info.adv_home_agent_flag = parse_bool(&tokens)?;
                }
                "advintervalopt" => {
                    iface.mobile_ipv6.adv_interval_opt = parse_bool(&tokens)?;
                }
                "advhomeagentinfo" => {
                    iface.mobile_ipv6.adv_home_agent_info = parse_bool(&tokens)?;
                }
                "homeagentpreference" => {
                    iface.mobile_ipv6.home_agent_preference = parse_u16(&tokens, line_no + 1)?;
                }
                "homeagentlifetime" => {
                    iface.mobile_ipv6.home_agent_lifetime = parse_i32(&tokens, line_no + 1)?;
                }
                "clients" => {
                    for addr_str in &tokens[1..] {
                        let addr = addr_str.parse::<Ipv6Addr>()
                            .map_err(|e| RadvdError::parse(format!(
                                "Line {}: invalid client address {}: {}",
                                line_no + 1, addr_str, e
                            )))?;
                        iface.client_list.push(Client {
                            address: addr,
                            ignored: false,
                        });
                    }
                }
                
                // Prefix definition
                "prefix" => {
                    if tokens.len() < 2 {
                        return Err(RadvdError::parse(format!(
                            "Line {}: prefix missing address",
                            line_no + 1
                        )));
                    }
                    let (addr, len) = parse_prefix(&tokens[1])?;
                    let mut prefix = AdvPrefix::default();
                    prefix.prefix = addr;
                    prefix.prefix_len = len;
                    current_prefix = Some(prefix);
                }
                
                // Route definition
                "route" => {
                    if tokens.len() < 2 {
                        return Err(RadvdError::parse(format!(
                            "Line {}: route missing address",
                            line_no + 1
                        )));
                    }
                    let (addr, len) = parse_prefix(&tokens[1])?;
                    let mut route = AdvRoute::default();
                    route.prefix = addr;
                    route.prefix_len = len;
                    current_route = Some(route);
                }
                
                // RDNSS definition
                "rdnss" => {
                    let mut rdnss = AdvRdnss::default();
                    for addr_str in &tokens[1..] {
                        if addr_str.parse::<Ipv6Addr>().is_ok() {
                            rdnss.adv_rdnss_addresses.push(addr_str.parse().unwrap());
                        }
                    }
                    current_rdnss = Some(rdnss);
                }
                
                // DNSSL definition
                "dnssl" => {
                    let mut dnssl = AdvDnssl::default();
                    for suffix in &tokens[1..] {
                        dnssl.adv_dnssl_suffixes.push(suffix.to_string());
                    }
                    current_dnssl = Some(dnssl);
                }
                
                _ => {
                    // Check if we're inside a prefix block
                    if let Some(ref mut prefix) = current_prefix {
                        match keyword.as_str() {
                            "advonlink" => prefix.adv_on_link_flag = parse_bool(&tokens)?,
                            "advautonomous" => prefix.adv_autonomous_flag = parse_bool(&tokens)?,
                            "advvalidlifetime" => prefix.adv_valid_lifetime = parse_u32(&tokens, line_no + 1)?,
                            "advpreferredlifetime" => prefix.adv_preferred_lifetime = parse_u32(&tokens, line_no + 1)?,
                            "deprecateprefix" => prefix.deprecate_prefix_flag = parse_bool(&tokens)?,
                            "decrementlifetimes" => prefix.decrement_lifetimes_flag = parse_bool(&tokens)?,
                            "advrouteraddr" => prefix.adv_router_addr = parse_bool(&tokens)?,
                            "base6to4interface" => {
                                if tokens.len() > 1 {
                                    prefix.if6to4 = Some(tokens[1].to_string());
                                }
                            }
                            "base6interface" => {
                                if tokens.len() > 1 {
                                    prefix.if6 = Some(tokens[1].to_string());
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }
                    
                    // Check if we're inside a route block
                    if let Some(ref mut route) = current_route {
                        match keyword.as_str() {
                            "advroutepreference" => {
                                let pref = parse_string(&tokens, line_no + 1)?.to_lowercase();
                                route.adv_route_preference = match pref.as_str() {
                                    "low" => RouterPreference::Low,
                                    "medium" => RouterPreference::Medium,
                                    "high" => RouterPreference::High,
                                    _ => RouterPreference::Medium,
                                };
                            }
                            "advroutelifetime" => route.adv_route_lifetime = parse_u32(&tokens, line_no + 1)?,
                            "removeroute" => route.remove_route_flag = parse_bool(&tokens)?,
                            _ => {}
                        }
                        continue;
                    }
                    
                    // Check if we're inside an RDNSS block
                    if let Some(ref mut rdnss) = current_rdnss {
                        match keyword.as_str() {
                            "advrdnsslifetime" => rdnss.adv_rdnss_lifetime = parse_u32(&tokens, line_no + 1)?,
                            "flushrdnss" => rdnss.flush_rdnss_flag = parse_bool(&tokens)?,
                            _ => {}
                        }
                        continue;
                    }
                    
                    // Check if we're inside a DNSSL block
                    if let Some(ref mut dnssl) = current_dnssl {
                        match keyword.as_str() {
                            "advdnssllifetime" => dnssl.adv_dnssl_lifetime = parse_u32(&tokens, line_no + 1)?,
                            "flushdnssl" => dnssl.flush_dnssl_flag = parse_bool(&tokens)?,
                            _ => {}
                        }
                        continue;
                    }
                }
            }
        }
    }
    
    // Don't forget the last interface
    if let Some(iface) = current_iface {
        config.interfaces.push(iface);
    }
    
    // Validate the configuration
    for iface in &config.interfaces {
        iface.validate()?;
    }
    
    Ok(config)
}

// Helper parsing functions
fn parse_bool(tokens: &[String]) -> RadvdResult<bool> {
    if tokens.len() < 2 {
        return Err(RadvdError::parse("Missing boolean value"));
    }
    match tokens[1].to_lowercase().as_str() {
        "on" | "yes" | "true" | "1" => Ok(true),
        "off" | "no" | "false" | "0" => Ok(false),
        _ => Err(RadvdError::parse(format!("Invalid boolean value: {}", tokens[1]))),
    }
}

fn parse_f64(tokens: &[String], line: usize) -> RadvdResult<f64> {
    if tokens.len() < 2 {
        return Err(RadvdError::parse(format!("Line {}: missing value", line)));
    }
    tokens[1].parse::<f64>()
        .map_err(|e| RadvdError::parse(format!("Line {}: invalid number: {}", line, e)))
}

fn parse_u32(tokens: &[String], line: usize) -> RadvdResult<u32> {
    if tokens.len() < 2 {
        return Err(RadvdError::parse(format!("Line {}: missing value", line)));
    }
    tokens[1].parse::<u32>()
        .map_err(|e| RadvdError::parse(format!("Line {}: invalid number: {}", line, e)))
}

fn parse_u16(tokens: &[String], line: usize) -> RadvdResult<u16> {
    if tokens.len() < 2 {
        return Err(RadvdError::parse(format!("Line {}: missing value", line)));
    }
    tokens[1].parse::<u16>()
        .map_err(|e| RadvdError::parse(format!("Line {}: invalid number: {}", line, e)))
}

fn parse_u8(tokens: &[String], line: usize) -> RadvdResult<u8> {
    if tokens.len() < 2 {
        return Err(RadvdError::parse(format!("Line {}: missing value", line)));
    }
    tokens[1].parse::<u8>()
        .map_err(|e| RadvdError::parse(format!("Line {}: invalid number: {}", line, e)))
}

fn parse_i32(tokens: &[String], line: usize) -> RadvdResult<i32> {
    if tokens.len() < 2 {
        return Err(RadvdError::parse(format!("Line {}: missing value", line)));
    }
    tokens[1].parse::<i32>()
        .map_err(|e| RadvdError::parse(format!("Line {}: invalid number: {}", line, e)))
}

fn parse_string(tokens: &[String], line: usize) -> RadvdResult<String> {
    if tokens.len() < 2 {
        return Err(RadvdError::parse(format!("Line {}: missing value", line)));
    }
    Ok(tokens[1].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_config() {
        let config_str = r#"
interface eth0 {
    AdvSendAdvert on;
    MaxRtrAdvInterval 30;
    MinRtrAdvInterval 10;
    
    prefix 2001:db8::/64 {
        AdvOnLink on;
        AdvAutonomous on;
    };
};
"#;
        
        let config = parse_config(config_str).unwrap();
        assert_eq!(config.interfaces.len(), 1);
        
        let iface = &config.interfaces[0];
        assert_eq!(iface.props.name, "eth0");
        assert!(iface.adv_send_advert);
        assert_eq!(iface.max_rtr_adv_interval, 30.0);
        assert_eq!(iface.adv_prefix_list.len(), 1);
    }

    #[test]
    fn test_parse_complex_config() {
        let config_str = r#"
interface eth0 {
    AdvSendAdvert on;
    MaxRtrAdvInterval 10;
    AdvDefaultPreference high;
    
    prefix 2001:db8:1::/64 {
        AdvOnLink on;
        AdvAutonomous on;
        AdvValidLifetime 86400;
        AdvPreferredLifetime 14400;
    };
    
    RDNSS 2001:db8::1 2001:db8::2 {
        AdvRDNSSLifetime 30;
    };
    
    DNSSL example.com {
        AdvDNSSLLifetime 30;
    };
};
"#;
        
        let config = parse_config(config_str).unwrap();
        assert_eq!(config.interfaces.len(), 1);
        
        let iface = &config.interfaces[0];
        assert_eq!(iface.adv_rdnss_list.len(), 1);
        assert_eq!(iface.adv_dnssl_list.len(), 1);
    }
}
