use serde::{Deserialize, Serialize};

/// Type of technical evidence observed
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceType {
    ActiveProcess,
    RegistryRunKey,
    ScheduledTask,
    SystemDaemonService,
    StartupFolderItem,
    WmiSubscription,
    InputHookApi,
    ScreenCaptureApi,
    KeyboardFilterDriver,
    NetworkSocketListener,
    UntrustedRootCertificate,
    SystemProxySetting,
    HostsFileTampering,
    ProcessTracerPtrace,
    SecurityFrameworkClient,
    UnsignedBinaryExecution,
    KnownFileArtifact,
    HardwareCaptureAccess,
    CommandAndControlBeacon,
}

/// Strongly typed container for evidence details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceData {
    Process {
        pid: u32,
        name: String,
        exe_path: Option<String>,
        command_line: Option<String>,
    },
    Registry {
        hive: String,
        path: String,
        value_name: Option<String>,
        value_data: Option<String>,
    },
    Service {
        name: String,
        display_name: Option<String>,
        binary_path: Option<String>,
        start_type: Option<String>,
    },
    File {
        path: String,
        sha256: Option<String>,
        is_signed: Option<bool>,
    },
    Network {
        protocol: String,
        local_address: String,
        remote_address: Option<String>,
        pid: Option<u32>,
    },
    HardwareAccess {
        device_type: String,
        application: String,
        is_active: bool,
    },
    Generic {
        key: String,
        value: String,
    },
}

/// A piece of technical evidence collected from the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: EvidenceType,
    pub collector: String,
    pub description: String,
    pub technical_detail: String,
    pub data: Option<EvidenceData>,
}

impl Evidence {
    pub fn new(
        evidence_type: EvidenceType,
        collector: impl Into<String>,
        description: impl Into<String>,
        technical_detail: impl Into<String>,
    ) -> Self {
        Self {
            evidence_type,
            collector: collector.into(),
            description: description.into(),
            technical_detail: technical_detail.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: EvidenceData) -> Self {
        self.data = Some(data);
        self
    }
}
