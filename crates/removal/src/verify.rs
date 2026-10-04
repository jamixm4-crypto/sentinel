use sentinel_core::Finding;

pub struct VerificationResult {
    pub is_completely_cleared: bool,
    pub lingering_artifacts: Vec<String>,
}

/// Verify that removed items no longer exist in the system
pub fn verify_removal(finding: &Finding) -> VerificationResult {
    let mut lingering = Vec::new();

    // 1. Check if files still exist
    for step in &finding.removal_steps.steps {
        if let sentinel_core::RemovalAction::QuarantineFile { source_path }
        | sentinel_core::RemovalAction::DeleteFile { path: source_path } = &step.action
        {
            if std::path::Path::new(source_path).exists() {
                lingering.push(format!("File/Directory still present: {}", source_path));
            }
        }
    }

    // 2. Check if processes are running
    #[cfg(target_os = "windows")]
    {
        for step in &finding.removal_steps.steps {
            if let sentinel_core::RemovalAction::TerminateProcess { name } = &step.action {
                let output = std::process::Command::new("tasklist")
                    .args(["/FI", &format!("IMAGENAME eq {}", name)])
                    .output();
                if let Ok(out) = output {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if text.contains(name) {
                        lingering.push(format!("Process still running: {}", name));
                    }
                }
            }
        }
    }

    VerificationResult {
        is_completely_cleared: lingering.is_empty(),
        lingering_artifacts: lingering,
    }
}
