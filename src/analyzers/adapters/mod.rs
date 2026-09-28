pub mod authorino;
pub mod nfd;

use kube::Client;
use serde::{Deserialize, Serialize};

use crate::analyzers::inspect::InspectedResource;
use crate::analyzers::olm::OperatorInstance;
use crate::kube::scanner::SharedPlanner;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterEvidence {
    pub adapter_id: String,
    pub source_commit: String,
    pub source_url: String,
    pub cleanup_function: String,
    pub naming_function: String,
    pub matched_csv_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterResolution {
    Resolved,
    TargetMissing,
    Unknown,
}

impl std::fmt::Display for AdapterResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterResolution::Resolved => write!(f, "Resolved"),
            AdapterResolution::TargetMissing => write!(f, "TargetMissing"),
            AdapterResolution::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterReportStatus {
    Applied,
    NotApplicable,
    Unknown,
}

impl std::fmt::Display for AdapterReportStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterReportStatus::Applied => write!(f, "Applied"),
            AdapterReportStatus::NotApplicable => write!(f, "NotApplicable"),
            AdapterReportStatus::Unknown => write!(f, "Unknown"),
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
    pub status: AdapterReportStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<AdapterEvidence>,
    pub results: Vec<AdapterResult>,
    pub diagnostics: Vec<String>,
    pub incomplete: bool,
}

pub async fn run_adapters(
    client: &Client,
    operator: &OperatorInstance,
    planner: Option<&SharedPlanner>,
    cr_resources: &[InspectedResource],
) -> Vec<AdapterReport> {
    let mut reports = Vec::new();

    if authorino::matches_operator(operator) {
        let roots = authorino::find_authorino_roots(cr_resources);
        if let Some(p) = planner {
            reports.push(authorino::discover(client, operator, p, &roots).await);
        } else {
            reports.push(AdapterReport {
                adapter_id: authorino::ADAPTER_ID.to_string(),
                status: AdapterReportStatus::Unknown,
                status_reason: Some("no query planner available".to_string()),
                evidence: None,
                results: vec![],
                diagnostics: vec![],
                incomplete: false,
            });
        }
    }

    if nfd::matches_operator(operator) {
        let roots = nfd::find_nfd_roots(cr_resources);
        if let Some(p) = planner {
            reports.push(nfd::discover(client, operator, p, &roots).await);
        } else {
            reports.push(AdapterReport {
                adapter_id: nfd::ADAPTER_ID.to_string(),
                status: AdapterReportStatus::Unknown,
                status_reason: Some("no query planner available".to_string()),
                evidence: None,
                results: vec![],
                diagnostics: vec![],
                incomplete: false,
            });
        }
    }

    reports
}

pub struct MergeResult {
    pub resources: Vec<InspectedResource>,
    pub warnings: Vec<String>,
    pub incomplete_count: usize,
}

pub fn merge_adapter_reports(reports: &[AdapterReport]) -> MergeResult {
    let mut resources = Vec::new();
    let mut warnings = Vec::new();
    let mut incomplete_count = 0usize;

    for report in reports {
        if report.status == AdapterReportStatus::NotApplicable {
            continue;
        }
        for r in &report.results {
            if r.resolution == AdapterResolution::Resolved && r.resource.id.uid.is_some() {
                resources.push(r.resource.clone());
            }
        }
        if report.incomplete {
            warnings.push(format!(
                "adapter {}: incomplete (some queries failed or returned errors)",
                report.adapter_id
            ));
            incomplete_count += 1;
        }
    }

    MergeResult {
        resources,
        warnings,
        incomplete_count,
    }
}
