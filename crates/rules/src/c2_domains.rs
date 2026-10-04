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
    }
}
