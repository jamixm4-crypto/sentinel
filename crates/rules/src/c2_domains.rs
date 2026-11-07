//! Embedded Stalkerware and Surveillance Command-and-Control (C2) Indicators
//! Derived from open threat intelligence feeds (AssoEchap stalkerware-indicators, TinyCheck, Citizen Lab).

pub static KNOWN_C2_DOMAINS: &[&str] = &[
    // FlexiSPY
    "flexispy.com",
    "admin.flexispy.com",
    "api.flexispy.com",
    "ecom.flexispy.com",
    "flxsp.com",
    "flxsp.net",
    
    // mSpy & EyeZy
    "mspyonline.com",
    "cp.mspyonline.com",
    "mspy.com",
    "getmspy.net",
    "api.thd.cc",
    "a.thd.cc",
    "eyezyapp.thd.cc",
    "eyezy.com",

    // Refog
    "refog.com",
    "account.refog.com",
    "downloads.refog.com",
    "dev2.refog.com",

    // Hoverwatch & Snoopza
    "hoverwatch.com",
    "dev.hoverwatch.com",
    "snoopza.com",
    "api.snoopza.com",
    "app.snoopza.com",
    "flower.snoopza.com",
    "get.snoopza.com",

    // Spyrix & Actual Keylogger
    "spyrix.com",
    "api.spyrix.com",
    "actualkeylogger.com",
    "softexe.com",

    // WebWatcher / Awareness Technologies
    "webwatcher.com",
    "webwatcherdata.com",
    "data.webwatcherdata.com",
    "api.awarenesstechnologies.com",
    "apitest.awarenesstechnologies.com",

    // KidLogger
    "kidlogger.net",
    "logger.mobi",
    "account.logger.mobi",
    "api.logger.mobi",

    // TheTruthSpy / Copy9 / HelloSpy
    "thetruthspy.com",
    "copy9.com",
    "copy9db.com",
    "hellospy.com",
    "1topspy.com",
    "maxxspy.com",
    "guestspy.com",

    // Cocospy / Spyic / Spylix / Minspy
    "cocospy.com",
    "spyic.com",
    "spylix.com",
    "api.spylix.com",
    "minspy.com",
    "neatspy.com",

    // iKeyMonitor / ClevGuard
    "ikeymonitor.com",
    "clevguard.com",
    "api.clevguard.com",
    "clevguard.net",

    // SpyBubble / Cerberus / pcTattletale
    "spybubble.com",
    "cerberusapp.com",
    "pctattletale.com",
    "pcpandora.com",
    "wolfeye.de",
    "remotespy.com",
    "moniterro.com",

    // Teramind / StaffCop / Kickidler / Hubstaff C2
    "teramind.co",
    "tmc.teramind.co",
    "staffcop.ru",
    "kickidler.com",
    "hubstaff.com",
    "monitask.com",
    "activtrak.com",
    "veriato.com",

    // Additional prominent commercial stalkerware domains
    "spappmonitoring.com",
    "spyphoneapp.com",
    "tispy.net",
    "blurspy.com",
    "spyhuman.com",
    "catwatchful.com",
    "ttspy.com",
    "ogymogy.com",
    "thewispy.com",
    "trackview.net",
    "reptilicus.net",
    "vkur.se",
    "android-monitor.ru",
    "cell-phones-tracker.net",
    "easyphonetrack.com",
    "cellphone-remote-tracker.com",
    "brunoespiao.com.br",
];

/// Match a domain or IP against the embedded database of known stalkerware C2 infrastructure.
/// Returns the matched C2 indicator if detected.
pub fn matches_known_c2(host: &str) -> Option<&'static str> {
    let host_lower = host.trim().to_lowercase();
    let host_clean = host_lower.split(':').next().unwrap_or(&host_lower);

    for &c2 in KNOWN_C2_DOMAINS {
        if host_clean == c2 || host_clean.ends_with(&format!(".{}", c2)) {
            return Some(c2);
        }
    }
    None
}

/// Matches a domain or IP against embedded C2 domains and additional custom C2 domain indicators.
pub fn matches_c2_with_custom(host: &str, custom_list: &[String]) -> Option<String> {
    let host_lower = host.trim().to_lowercase();
    let host_clean = host_lower.split(':').next().unwrap_or(&host_lower);

    if let Some(c2) = matches_known_c2(host_clean) {
        return Some(c2.to_string());
    }

    for c2 in custom_list {
        let c2_clean = c2.trim().to_lowercase();
        if !c2_clean.is_empty() && (host_clean == c2_clean || host_clean.ends_with(&format!(".{}", c2_clean))) {
            return Some(c2_clean);
        }
    }
    None
}

/// Returns all unique C2 domains combining embedded domains with optional custom domains.
pub fn get_all_c2_domains(custom_list: &[String]) -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for d in KNOWN_C2_DOMAINS {
        set.insert(d.to_string());
    }
    for c in custom_list {
        let clean = c.trim().to_lowercase();
        if !clean.is_empty() {
            set.insert(clean);
        }
    }
    set.into_iter().collect()
}

/// Exports C2 domains as Suricata / Snort rules compatible with TinyCheck, pfSense, and OPNSense.
pub fn export_suricata_rules(custom_list: &[String], sid_start: u32) -> String {
    let domains = get_all_c2_domains(custom_list);
    let mut out = String::with_capacity(domains.len() * 300);
    out.push_str("# -----------------------------------------------------------------------------\n");
    out.push_str("# Sentinel Anti-Surveillance C2 Rules for Suricata / Snort / TinyCheck\n");
    out.push_str("# Generated offline by Sentinel (https://github.com/jamixm4-crypto/sentinel)\n");
    out.push_str(&format!("# Total indicators: {}\n", domains.len()));
    out.push_str("# -----------------------------------------------------------------------------\n\n");

    let mut sid = sid_start;
    for domain in domains {
        // DNS Query inspection
        out.push_str(&format!(
            "alert dns $HOME_NET any -> any any (msg:\"SENTINEL Stalkerware C2 DNS Query: {domain}\"; dns.query; content:\"{domain}\"; nocase; endswith; classtype:trojan-activity; sid:{sid}; rev:1;)\n"
        ));
        // TLS SNI inspection
        out.push_str(&format!(
            "alert tls $HOME_NET any -> any 443 (msg:\"SENTINEL Stalkerware C2 TLS SNI: {domain}\"; tls.sni; content:\"{domain}\"; nocase; endswith; classtype:trojan-activity; sid:{}; rev:1;)\n",
            sid + 100_000
        ));
        // HTTP Host inspection
        out.push_str(&format!(
            "alert http $HOME_NET any -> any any (msg:\"SENTINEL Stalkerware C2 HTTP Host: {domain}\"; http.host; content:\"{domain}\"; nocase; endswith; classtype:trojan-activity; sid:{}; rev:1;)\n\n",
            sid + 200_000
        ));
        sid += 1;
    }
    out
}

/// Exports C2 domains in hosts format (0.0.0.0 domain) for Pi-hole, AdGuard Home, or /etc/hosts.
pub fn export_hosts_format(custom_list: &[String]) -> String {
    let domains = get_all_c2_domains(custom_list);
    let mut out = String::with_capacity(domains.len() * 40);
    out.push_str("# Sentinel Stalkerware C2 Blocklist (Hosts format)\n");
    out.push_str("# Compatible with Pi-hole, AdGuard Home, and local hosts file\n\n");
    for d in domains {
        out.push_str(&format!("0.0.0.0 {}\n", d));
    }
    out
}

/// Exports C2 domains as plain list (one per line).
pub fn export_domains_list(custom_list: &[String]) -> String {
    let domains = get_all_c2_domains(custom_list);
    domains.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c2_exact_and_subdomain_matching() {
        assert_eq!(matches_known_c2("flexispy.com"), Some("flexispy.com"));
        assert_eq!(matches_known_c2("api.flexispy.com"), Some("flexispy.com"));
        assert_eq!(matches_known_c2("sub.data.webwatcherdata.com:443"), Some("webwatcherdata.com"));
        assert_eq!(matches_known_c2("google.com"), None);
        assert_eq!(matches_known_c2("microsoft.com"), None);

        let custom = vec!["malicious-tracker.org".to_string()];
        assert_eq!(
            matches_c2_with_custom("api.malicious-tracker.org:8443", &custom),
            Some("malicious-tracker.org".to_string())
        );
        assert_eq!(
            matches_c2_with_custom("flexispy.com", &custom),
            Some("flexispy.com".to_string())
        );
        assert_eq!(matches_c2_with_custom("safe.org", &custom), None);

        let suricata = export_suricata_rules(&custom, 9000000);
        assert!(suricata.contains("SENTINEL Stalkerware C2 DNS Query: flexispy.com"));
        assert!(suricata.contains("malicious-tracker.org"));
        assert!(suricata.contains("sid:9000000"));

        let hosts = export_hosts_format(&custom);
        assert!(hosts.contains("0.0.0.0 flexispy.com"));
        assert!(hosts.contains("0.0.0.0 malicious-tracker.org"));

        let list = export_domains_list(&custom);
        assert!(list.contains("flexispy.com\n"));
        assert!(list.contains("malicious-tracker.org\n"));
    }
}
