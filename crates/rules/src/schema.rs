use serde::{Deserialize, Serialize};
use sentinel_core::{Category, RemovalPolicy, Severity};

/// Complete declarative rule for detecting surveillance software
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub version: u32,
    pub category: Category,
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub base_confidence: f32,
    pub removal_policy: RemovalPolicy,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    pub description: String,
    #[serde(default)]
    pub is_legitimate_use_likely: bool,
    #[serde(default)]
    pub safety_warning: Option<String>,
    
    pub detection: DetectionCriteria,
    #[serde(default)]
    pub condition: Option<ConditionExpression>,
    #[serde(default)]
    pub removal: Option<RemovalInstructions>,
    #[serde(default)]
    pub references: Vec<String>,
}

fn default_confidence() -> f32 {
    0.8
}

/// Multi-modal detection targets
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectionCriteria {
    #[serde(default)]
    pub processes: Vec<ProcessCriteria>,
    #[serde(default)]
    pub registry_keys: Vec<RegistryCriteria>,
    #[serde(default)]
    pub services: Vec<ServiceCriteria>,
    #[serde(default)]
    pub scheduled_tasks: Vec<TaskCriteria>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub network_domains: Vec<String>,
    #[serde(default)]
    pub network_ports: Vec<u16>,
    #[serde(default)]
    pub launch_agents: Vec<String>,
    #[serde(default)]
    pub systemd_units: Vec<String>,
    #[serde(default)]
    pub bundle_ids: Vec<String>,
    #[serde(default)]
    pub package_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCriteria {
    pub name: String,
    #[serde(default)]
    pub cmdline_regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryCriteria {
    pub hive: String, // HKLM, HKCU
    pub path: String,
    #[serde(default)]
    pub value_name: Option<String>,
    #[serde(default)]
    pub value_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCriteria {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCriteria {
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionExpression {
    #[serde(default)]
    pub any_of: Vec<String>,
    #[serde(default)]
    pub all_of: Vec<String>,
    #[serde(default)]
    pub min_matches: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemovalInstructions {
    #[serde(default)]
    pub uninstall_key: Option<String>,
    #[serde(default)]
    pub services_to_stop: Vec<String>,
    #[serde(default)]
    pub services_to_delete: Vec<String>,
    #[serde(default)]
    pub processes_to_kill: Vec<String>,
    #[serde(default)]
    pub paths_to_remove: Vec<String>,
    #[serde(default)]
    pub registry_values_to_clean: Vec<RegistryCriteria>,
    #[serde(default)]
    pub manual_steps_windows: Option<String>,
    #[serde(default)]
    pub manual_steps_linux: Option<String>,
    #[serde(default)]
    pub manual_steps_macos: Option<String>,
}
