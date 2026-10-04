use std::path::Path;
use thiserror::Error;

use crate::schema::Rule;

#[derive(Error, Debug)]
pub enum RuleLoadError {
    #[error("Failed to read rule file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("Failed to parse YAML rule {path}: {source}")]
    Yaml {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("Rule validation failed for {id}: {reason}")]
    Validation { id: String, reason: String },
}

/// Load and validate a single YAML rule file
pub fn load_rule_from_str(content: &str, file_name: &str) -> Result<Rule, RuleLoadError> {
    let rule: Rule = serde_yaml::from_str(content).map_err(|e| RuleLoadError::Yaml {
        path: file_name.to_string(),
        source: e,
    })?;

    validate_rule(&rule)?;
    Ok(rule)
}

/// Load and validate a single rule file from a path
pub fn load_rule_file(path: &Path) -> Result<Rule, RuleLoadError> {
    let content = std::fs::read_to_string(path).map_err(|e| RuleLoadError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    load_rule_from_str(&content, &path.display().to_string())
}

/// Load all rules recursively from a directory
pub fn load_rules_from_dir(dir: &Path) -> Result<Vec<Rule>, RuleLoadError> {
    let mut rules = Vec::new();
    if !dir.exists() {
        return Ok(rules);
    }

    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "yml" || ext == "yaml" {
                    match load_rule_file(path) {
                        Ok(rule) => rules.push(rule),
                        Err(e) => {
                            tracing::warn!("Failed loading rule {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }
    }

    Ok(rules)
}

/// Semantic validation of a rule
pub fn validate_rule(rule: &Rule) -> Result<(), RuleLoadError> {
    if rule.id.trim().is_empty() {
        return Err(RuleLoadError::Validation {
            id: rule.id.clone(),
            reason: "Rule ID cannot be empty".into(),
        });
    }
    if rule.name.trim().is_empty() {
        return Err(RuleLoadError::Validation {
            id: rule.id.clone(),
            reason: "Rule Name cannot be empty".into(),
        });
    }
    if rule.description.trim().is_empty() {
        return Err(RuleLoadError::Validation {
            id: rule.id.clone(),
            reason: "Rule Description cannot be empty".into(),
        });
    }
    Ok(())
}
