//! Sentinel Rules - YAML Rule Database, Schema, and Matcher

pub mod c2_domains;
pub mod loader;
pub mod matcher;
pub mod schema;

pub use c2_domains::{matches_known_c2, KNOWN_C2_DOMAINS};
pub use loader::{load_rule_file, load_rule_from_str, load_rules_from_dir, validate_rule, RuleLoadError};
pub use matcher::{RuleMatch, RuleMatcher};
pub use schema::{
    ConditionExpression, DetectionCriteria, ProcessCriteria, RegistryCriteria, RemovalInstructions, Rule,
    ServiceCriteria, TaskCriteria,
};

/// Get the complete embedded rules collection compiled into the binary
pub fn get_embedded_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    let embedded_raw = &[
        include_str!("../../../rules/stalkerware/spyrix.yml"),
        include_str!("../../../rules/stalkerware/mspy.yml"),
        include_str!("../../../rules/stalkerware/flexispy.yml"),
        include_str!("../../../rules/stalkerware/refog.yml"),
        include_str!("../../../rules/stalkerware/actual_keylogger.yml"),
        include_str!("../../../rules/stalkerware/kidlogger.yml"),
        include_str!("../../../rules/stalkerware/pctattletale.yml"),
        include_str!("../../../rules/stalkerware/hoverwatch.yml"),
        include_str!("../../../rules/stalkerware/cocospy.yml"),
        include_str!("../../../rules/stalkerware/ikey_monitor.yml"),
        include_str!("../../../rules/stalkerware/thetruthspy.yml"),
        include_str!("../../../rules/stalkerware/wolfeye.yml"),
        include_str!("../../../rules/stalkerware/eyezy.yml"),
        include_str!("../../../rules/stalkerware/spybubble.yml"),
        include_str!("../../../rules/stalkerware/cerberus.yml"),
        include_str!("../../../rules/stalkerware/remotespy.yml"),
        include_str!("../../../rules/stalkerware/moniterro.yml"),
        include_str!("../../../rules/stalkerware/pc_pandora.yml"),

        include_str!("../../../rules/stalkerware/spapp_monitoring.yml"),
        include_str!("../../../rules/stalkerware/spyic.yml"),
        include_str!("../../../rules/stalkerware/sentrypc.yml"),
        include_str!("../../../rules/stalkerware/softactivity.yml"),
        include_str!("../../../rules/stalkerware/spytech_spyagent.yml"),
        include_str!("../../../rules/stalkerware/webwatcher.yml"),
        include_str!("../../../rules/stalkerware/netvizor.yml"),
        include_str!("../../../rules/stalkerware/kidinspector.yml"),
        include_str!("../../../rules/stalkerware/elite_keylogger.yml"),
        include_str!("../../../rules/stalkerware/micro_keylogger.yml"),

        include_str!("../../../rules/corporate/teramind.yml"),
        include_str!("../../../rules/corporate/activtrak.yml"),
        include_str!("../../../rules/corporate/hubstaff.yml"),
        include_str!("../../../rules/corporate/veriato.yml"),
        include_str!("../../../rules/corporate/interguard.yml"),
        include_str!("../../../rules/corporate/kickidler.yml"),
        include_str!("../../../rules/corporate/time_doctor.yml"),
        include_str!("../../../rules/corporate/desktime.yml"),
        include_str!("../../../rules/corporate/monitask.yml"),
        include_str!("../../../rules/corporate/workpuls.yml"),
        include_str!("../../../rules/corporate/clevercontrol.yml"),
        include_str!("../../../rules/corporate/staffcop.yml"),
        include_str!("../../../rules/corporate/rhubarb.yml"),
        include_str!("../../../rules/corporate/qustodio.yml"),
        include_str!("../../../rules/corporate/famisafe.yml"),
        include_str!("../../../rules/corporate/clevercontrol_cloud.yml"),

        include_str!("../../../rules/remote_access/teamviewer.yml"),
        include_str!("../../../rules/remote_access/anydesk.yml"),
        include_str!("../../../rules/remote_access/rustdesk.yml"),
        include_str!("../../../rules/remote_access/screenconnect.yml"),
        include_str!("../../../rules/remote_access/netsupport.yml"),
        include_str!("../../../rules/remote_access/splashtop.yml"),
        include_str!("../../../rules/remote_access/vnc.yml"),
        include_str!("../../../rules/remote_access/dwservice.yml"),
        include_str!("../../../rules/remote_access/parsec.yml"),
        include_str!("../../../rules/remote_access/radmin.yml"),
        include_str!("../../../rules/remote_access/chrome_remote_desktop.yml"),
        include_str!("../../../rules/remote_access/ammyy_admin.yml"),
        include_str!("../../../rules/remote_access/logmein.yml"),
        include_str!("../../../rules/remote_access/logmein_goto.yml"),
        include_str!("../../../rules/remote_access/tightvnc.yml"),

        include_str!("../../../rules/edr_mdm/crowdstrike.yml"),
        include_str!("../../../rules/edr_mdm/sentinelone.yml"),
        include_str!("../../../rules/edr_mdm/microsoft_intune.yml"),
        include_str!("../../../rules/edr_mdm/carbon_black.yml"),
        include_str!("../../../rules/edr_mdm/jamf.yml"),
        include_str!("../../../rules/edr_mdm/mosyle.yml"),
        include_str!("../../../rules/edr_mdm/kandji.yml"),
        include_str!("../../../rules/edr_mdm/microsoft_defender.yml"),

        include_str!("../../../rules/legitimate/obs.yml"),
        include_str!("../../../rules/legitimate/zoom.yml"),
        include_str!("../../../rules/legitimate/teams.yml"),
        include_str!("../../../rules/legitimate/discord.yml"),
        include_str!("../../../rules/legitimate/steam_overlay.yml"),
        include_str!("../../../rules/legitimate/nvidia_shadowplay.yml"),
        include_str!("../../../rules/legitimate/autohotkey.yml"),
        include_str!("../../../rules/legitimate/password_managers.yml"),
    ];

    for (idx, raw) in embedded_raw.iter().enumerate() {
        match load_rule_from_str(raw, &format!("embedded_rule_{}", idx)) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                tracing::error!("Failed to parse embedded rule {}: {}", idx, e);
            }
        }
    }

    rules
}
