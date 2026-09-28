pub mod authorino;

use kube::Client;
use serde::{Deserialize, Serialize};

use crate::analyzers::inspect::InspectedResource;
use crate::analyzers::olm::OperatorInstance;
use crate::kube::scanner::SharedPlanner;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterEvidence {
    pub adapter_id: String,
    pub source_revision: String,
    pub source_url: String,
    pub cleanup_rule: String,
    pub matched_csv_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterResolution {
    Resolved,
    TargetMissing,
    Unknown,
    UnsupportedVersion,
}

impl std::fmt::Display for AdapterResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterResolution::Resolved => write!(f, "Resolved"),
            AdapterResolution::TargetMissing => write!(f, "TargetMissing"),
            AdapterResolution::Unknown => write!(f, "Unknown"),
            AdapterResolution::UnsupportedVersion => write!(f, "UnsupportedVersion"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterResult {
    pub resource: InspectedResource,
    pub resolution: AdapterResolution,
    pub adapter_evidence: AdapterEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterReport {
    pub adapter_id: String,
    pub results: Vec<AdapterResult>,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    pub diagnostics: Vec<String>,
    pub incomplete: bool,
}

pub async fn run_adapters(
    client: &Client,
    operator: &OperatorInstance,
    planner: Option<&SharedPlanner>,
) -> Vec<AdapterReport> {
    let mut reports = Vec::new();

    if authorino::matches_operator(operator) {
        if let Some(p) = planner {
            reports.push(authorino::discover(client, operator, p).await);
        } else {
            reports.push(AdapterReport {
                adapter_id: authorino::ADAPTER_ID.to_string(),
                results: vec![],
                skipped: true,
                skip_reason: Some("no query planner available".to_string()),
                diagnostics: vec![],
                incomplete: false,
            });
        }
    }

    reports
}
