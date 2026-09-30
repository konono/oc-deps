//! Teardown command: plan, apply, resume, batch, status, explain.

use crate::analyzers::olm::{discover_operators, discover_operators_full};
use crate::cli::{OutputFormat, TeardownAction};
use crate::graph::evidence::build_evidence_graph;
use crate::kube::discovery::build_kind_lookup_cached;
use crate::kube::snapshot::build_snapshot;
use crate::teardown::explain::explain_resource;
use crate::teardown::journal::{self, RunJournal};
use crate::teardown::permit::MutationGate;
use crate::teardown::planner::{
    DecisionPolicy, generate_teardown_plan, load_plan_from_file, print_teardown_plan,
    resolve_operator_targets, save_plan_to_file,
};
use crate::teardown::progress::{check_plan_status, print_plan_status};
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::time::Instant;

pub(crate) fn apply_set_child_bypasses_cache(no_cache: bool, entry_index: usize) -> bool {
    no_cache && entry_index == 0
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplySetConfig {
    #[serde(rename = "description")]
    pub(crate) _description: Option<String>,
    #[serde(default)]
    pub(crate) defaults: ApplySetDefaults,
    pub(crate) operators: Vec<ApplySetEntry>,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplySetDefaults {
    #[serde(default)]
    approve_delete: ApplySetDeleteApprovals,
    #[serde(default)]
    preserve: Vec<String>,
}

pub use crate::teardown::plan::DeleteResourceSpec;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplySetEntry {
    pub(crate) name: String,
    #[serde(default)]
    approve_delete: ApplySetDeleteApprovals,
    #[serde(default)]
    preserve: Vec<String>,
    #[serde(default)]
    pub(crate) delete_resources: Vec<DeleteResourceSpec>,
}

pub(crate) struct EffectiveApplySetOptions {
    pub(crate) approve_delete: Vec<String>,
    pub(crate) preserve: Vec<String>,
    pub(crate) delete_resources: Vec<DeleteResourceSpec>,
}

impl ApplySetEntry {
    pub(crate) fn effective_options(
        &self,
        defaults: &ApplySetDefaults,
    ) -> EffectiveApplySetOptions {
        let mut approve_delete = defaults.approve_delete.cli_args();
        approve_delete.extend(self.approve_delete.cli_args());
        let mut seen_approvals = HashSet::new();
        approve_delete.retain(|value| seen_approvals.insert(value.clone()));

        let mut preserve = defaults.preserve.clone();
        preserve.extend(self.preserve.iter().cloned());
        let mut seen_preserves = HashSet::new();
        preserve.retain(|value| seen_preserves.insert(value.clone()));

        EffectiveApplySetOptions {
            approve_delete,
            preserve,
            delete_resources: self.delete_resources.clone(),
        }
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplySetDeleteApprovals {
    #[serde(default)]
    scopes: Vec<ApplySetApprovalScope>,
    #[serde(default)]
    resources: Vec<String>,
}

impl ApplySetDeleteApprovals {
    fn cli_args(&self) -> Vec<String> {
        self.scopes
            .iter()
            .map(|scope| scope.cli_arg().to_string())
            .chain(self.resources.iter().cloned())
            .collect()
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ApplySetApprovalScope {
    Root,
    Independent,
    LabelOnly,
    OperatorGroup,
}

impl ApplySetApprovalScope {
    fn cli_arg(&self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Independent => "independent",
            Self::LabelOnly => "label-only",
            Self::OperatorGroup => "operator-group",
        }
    }
}

use crate::teardown::planner::{
    build_execution_plan_from_teardown, inject_explicit_phase_into_teardown_plan,
    resolve_explicit_delete_targets, should_refresh_discovery,
};
use crate::teardown::workflow::{BatchOutcome, find_pending_explicit_cleanup_journal};

pub(crate) fn batch_summary(results: &[(String, BatchOutcome)]) -> (usize, usize, usize) {
    let s = results
        .iter()
        .filter(|(_, o)| *o == BatchOutcome::Succeeded)
        .count();
    let sk = results
        .iter()
        .filter(|(_, o)| *o == BatchOutcome::Skipped)
        .count();
    let f = results
        .iter()
        .filter(|(_, o)| matches!(o, BatchOutcome::Failed(_)))
        .count();
    (s, sk, f)
}

pub(crate) fn operator_matches_entry(
    op: &crate::analyzers::olm::OperatorInstance,
    entry_name: &str,
) -> bool {
    op.csv.name.starts_with(&format!("{}.", entry_name))
        || op.csv.name.starts_with(&format!("{}.v", entry_name))
        || op.package_name.as_deref() == Some(entry_name)
        || op.csv.name == entry_name
}

pub(crate) fn print_run_journal(j: &RunJournal) {
    eprintln!("Run:      {}", j.run_id);
    eprintln!("Operator: {}", j.operator.csv_name);
    eprintln!("State:    {:?}", j.state);
    eprintln!("Created:  {}", j.created_at);
    eprintln!("Updated:  {}", j.updated_at);
    eprintln!("Journal revision: {}", j.journal_revision);
    eprintln!("Audit revision:   {}", j.audit_revision);
    eprintln!();

    let exec = &j.execution;
    eprintln!(
        "Execution: {}/{} phases",
        exec.phases_completed, exec.phases_total
    );
    eprintln!(
        "  {} deleted, {} already gone, {} failed",
        exec.deleted.len(),
        exec.already_gone.len(),
        exec.failed.len()
    );

    if !exec.kept.is_empty() || !exec.reviewed.is_empty() {
        eprintln!(
            "\nPlanned preserved: {} KEEP, {} REVIEW",
            exec.kept.len(),
            exec.reviewed.len()
        );
    }
}

// discover_audit_scope, create_run_journal, build_operator_identity_snapshot,
// fetch_observed_identities moved to teardown::journal
// ExplicitCleanupResumeMode, explicit_cleanup_resume_mode, operator_snapshot_matches_entry,
// find_pending_explicit_cleanup_journal, select_pending_explicit_cleanup_journal,
// ResumeStage, classify_resume_stage moved to teardown::workflow
pub(crate) async fn handle_teardown(
    client: &::kube::Client,
    config: &::kube::config::Config,
    action: crate::cli::TeardownAction,
) -> anyhow::Result<()> {
    match action {
        TeardownAction::Plan {
            operators: operator_queries,
            output,
            refresh_discovery,
            prune_crds,
            approve_scope,
            approve_resource,
            keep_resource,
            delete_resource,
            file: save_plan_path,
        } => {
            // Early validation of delete-resource specs (before discovery)
            let explicit_specs: Vec<DeleteResourceSpec> = delete_resource
                .iter()
                .map(|s| DeleteResourceSpec::parse_cli_arg(s))
                .collect::<Result<Vec<_>>>()?;
            crate::teardown::workflow::validate_delete_resource_specs(&explicit_specs)?;

            let no_cache = should_refresh_discovery(refresh_discovery, explicit_specs.len());

            let mut approve_delete: Vec<String> = approve_scope
                .iter()
                .map(|s| s.cli_arg().to_string())
                .collect();
            approve_delete.extend(approve_resource.iter().cloned());
            let preserve = keep_resource.clone();
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, gvr_map, gk_map, gvk_map) =
                build_kind_lookup_cached(client, config, no_cache).await?;
            let t_discovery = t0.elapsed();

            let plan_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::kube::scanner::DEFAULT_API_CONCURRENCY,
            ));
            let plan_planner = crate::kube::planner::QueryPlanner::new(Some(plan_semaphore));
            let t_olm = Instant::now();
            eprint!("🔍 Discovering operators...");
            let all_operators =
                discover_operators_full(client, &kind_map, None, Some(plan_planner.clone()))
                    .await?;
            eprintln!(" found {} operators", all_operators.len());
            let t_olm = t_olm.elapsed();

            let target_indices = resolve_operator_targets(&operator_queries, &all_operators)?;
            let target_operators: Vec<&_> =
                target_indices.iter().map(|&i| &all_operators[i]).collect();

            let policy = DecisionPolicy::from_args(&approve_delete, &preserve);
            let t_plan = Instant::now();
            let plan = generate_teardown_plan(
                client,
                &target_operators,
                &all_operators,
                &kind_map,
                &gvr_map,
                &gk_map,
                &gvk_map,
                prune_crds,
                &policy,
                Some(plan_planner.clone()),
            )
            .await?;
            let t_plan = t_plan.elapsed();

            // Resolve explicit delete targets and inject into plan before display
            let mut plan = plan;
            let explicit_targets = if !explicit_specs.is_empty() {
                let targets =
                    resolve_explicit_delete_targets(client, &explicit_specs, &plan, &gk_map)
                        .await?;
                inject_explicit_phase_into_teardown_plan(&mut plan, &targets, &gk_map)?;
                targets
            } else {
                Vec::new()
            };

            print_teardown_plan(&plan, &output);

            // Save as runtime plan (debug)
            match save_plan_to_file(&plan) {
                Ok(path) => eprintln!("📄 Plan saved to {}", path),
                Err(e) => eprintln!("⚠ Could not save plan: {}", e),
            }

            // Build and save ExecutionPlan
            if let Some(ref save_path) = save_plan_path {
                let cluster_identity = journal::fetch_cluster_identity(client).await?;
                let mut exec_plan = build_execution_plan_from_teardown(
                    &plan,
                    &target_operators,
                    &cluster_identity,
                    prune_crds,
                    &approve_scope,
                    &approve_resource,
                    &keep_resource,
                )?;
                exec_plan.explicit_deletes = explicit_targets;

                crate::teardown::plan::save_execution_plan(&exec_plan, save_path)?;
                eprintln!("📄 Execution plan saved to {}", save_path);
            }

            eprintln!(
                "\n⏱ Discovery: {:.1}s, OLM: {:.1}s, Plan: {:.1}s, Total: {:.1}s",
                t_discovery.as_secs_f64(),
                t_olm.as_secs_f64(),
                t_plan.as_secs_f64(),
                t0.elapsed().as_secs_f64()
            );
        }
        TeardownAction::Apply {
            plan: plan_file,
            refresh_discovery,
            dry_run,
            yes,
            backup_dir,
        } => {
            // Load execution plan
            let exec_plan = crate::teardown::plan::load_execution_plan(&plan_file)?;
            eprintln!("📄 Loaded execution plan from {}", plan_file);

            // Create gate + Ctrl-C handler
            let gate = std::sync::Arc::new(MutationGate::new(16));
            if !dry_run {
                let gate_for_signal = gate.clone();
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        eprintln!("\n⏸ Pausing... waiting for active mutations to complete...");
                        gate_for_signal.close_and_drain().await;
                    }
                });
            }

            let apply_params = crate::teardown::workflow::ApplyParams {
                dry_run,
                backup_dir: backup_dir.as_deref(),
                skip_confirm: yes,
                refresh_discovery,
                gate: &gate,
            };
            let outcome = crate::teardown::workflow::apply_execution_plan(
                client,
                config,
                &exec_plan,
                &apply_params,
            )
            .await?;
            crate::teardown::workflow::require_completed(&outcome)?;
        }
        TeardownAction::Status {
            operators: operator_queries,
            refresh_discovery,
            plan_file,
        } => {
            let no_cache = refresh_discovery;
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, _gvr_map, gk_map, _gvk_map) =
                build_kind_lookup_cached(client, config, no_cache).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            let plan = if let Some(path) = plan_file {
                eprintln!("📄 Loading plan from {}", path);
                load_plan_from_file(&path)?
            } else {
                eprint!("🔍 Discovering operators...");
                let all_operators = discover_operators(client, &kind_map).await?;
                eprintln!(" found {} operators", all_operators.len());

                let target_indices = resolve_operator_targets(&operator_queries, &all_operators)?;
                let target_operators: Vec<&_> =
                    target_indices.iter().map(|&i| &all_operators[i]).collect();

                generate_teardown_plan(
                    client,
                    &target_operators,
                    &all_operators,
                    &kind_map,
                    &_gvr_map,
                    &gk_map,
                    &_gvk_map,
                    false,
                    &DecisionPolicy::empty(),
                    None,
                )
                .await?
            };

            eprint!("🔍 Checking resource status...");
            let statuses = check_plan_status(client, &plan, &kind_map, &gk_map).await;
            eprintln!(" done");

            print_plan_status(&plan, &statuses);
        }
        TeardownAction::Coverage {
            operators: operator_queries,
            output,
            refresh_discovery,
        } => {
            let no_cache = refresh_discovery;
            let (kind_map, gvr_map, gk_map, gvk_map) =
                build_kind_lookup_cached(client, config, no_cache).await?;
            let all_operators = discover_operators(client, &kind_map).await?;
            let target_indices = resolve_operator_targets(&operator_queries, &all_operators)?;
            let target_operators: Vec<&_> =
                target_indices.iter().map(|&i| &all_operators[i]).collect();

            let policy = DecisionPolicy::from_args(&[], &[]);
            let plan = generate_teardown_plan(
                client,
                &target_operators,
                &all_operators,
                &kind_map,
                &gvr_map,
                &gk_map,
                &gvk_map,
                false,
                &policy,
                None,
            )
            .await?;

            // Categorize plan actions
            let mut covered = Vec::new();
            let mut preserved = Vec::new();
            let mut not_covered = Vec::new();

            for phase in &plan.phases {
                for action in &phase.actions {
                    match action {
                        crate::teardown::planner::Action::Delete { resource, .. }
                        | crate::teardown::planner::Action::ExpectGone { resource, .. } => {
                            covered.push(resource.clone());
                        }
                        crate::teardown::planner::Action::Keep { resource, .. } => {
                            preserved.push(resource.clone());
                        }
                        crate::teardown::planner::Action::Review { resource, .. } => {
                            not_covered.push(resource.clone());
                        }
                        _ => {}
                    }
                }
            }

            match output {
                OutputFormat::Json => {
                    let json = serde_json::json!({
                        "coverage_scope": "plan-known-footprint",
                        "complete": false,
                        "note": "Coverage is limited to resources discovered by the plan. Resources outside operator-owned APIs, related CRDs, and namespace discovery are not included.",
                        "covered_by_plan": covered.len(),
                        "intentionally_preserved": preserved.len(),
                        "not_covered": not_covered.len(),
                        "covered": covered,
                        "preserved": preserved,
                        "not_covered_resources": not_covered,
                    });
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }
                _ => {
                    eprintln!(
                        "\n\x1b[1mCoverage\x1b[0m: {} covered, {} preserved, {} not covered",
                        covered.len(),
                        preserved.len(),
                        not_covered.len()
                    );
                    if !not_covered.is_empty() {
                        eprintln!("\n\x1b[33mNOT COVERED (REVIEW):\x1b[0m");
                        for r in &not_covered {
                            eprintln!(
                                "  {}/{}{}",
                                r.kind,
                                r.name,
                                r.namespace
                                    .as_ref()
                                    .map(|ns| format!(" ({})", ns))
                                    .unwrap_or_default()
                            );
                        }
                    }
                }
            }
        }
        TeardownAction::Explain {
            operators: operator_queries,
            resource,
            refresh_discovery,
        } => {
            let no_cache = refresh_discovery;
            let t0 = Instant::now();
            eprintln!("🔍 Discovering API resources...");
            let (kind_map, gvr_map, gk_map, gvk_map) =
                build_kind_lookup_cached(client, config, no_cache).await?;
            eprintln!("   Discovery: {:.1}s", t0.elapsed().as_secs_f64());

            eprint!("🔍 Discovering operators...");
            let all_operators = discover_operators(client, &kind_map).await?;
            eprintln!(" found {} operators", all_operators.len());

            let target_indices = resolve_operator_targets(&operator_queries, &all_operators)?;
            let target_operators: Vec<&_> =
                target_indices.iter().map(|&i| &all_operators[i]).collect();

            let plan = generate_teardown_plan(
                client,
                &target_operators,
                &all_operators,
                &kind_map,
                &gvr_map,
                &gk_map,
                &gvk_map,
                false,
                &DecisionPolicy::empty(),
                None,
            )
            .await?;

            let namespace = target_operators
                .first()
                .map(|op| op.install_namespace.as_str())
                .unwrap_or("default");

            let snapshot = build_snapshot(client, config, namespace, &kind_map, false).await?;

            let evidence_graph = build_evidence_graph(&snapshot, &all_operators);

            let explanation = explain_resource(&plan, &resource, &all_operators, &evidence_graph);
            println!("{}", explanation);
        }
        TeardownAction::Resume {
            operator,
            run,
            refresh_discovery,
        } => {
            let cluster_id = journal::fetch_cluster_identity(client).await?;

            let found = if let Some(run_id) = run {
                let path = journal::run_path(&cluster_id, &run_id)?;
                Some((journal::load_journal(&path)?, path))
            } else if let Some(op) = operator {
                journal::find_latest_run(&cluster_id, &op)?.map(|j| {
                    let path = journal::run_path(&cluster_id, &j.run_id)
                        .expect("run_path for found journal");
                    (j, path)
                })
            } else {
                bail!("Specify an operator name or --run <run-id>");
            };

            let (j, journal_path) = match found {
                Some(pair) => pair,
                None => bail!("No teardown run found to resume"),
            };

            // Create gate + Ctrl-C handler
            let gate = std::sync::Arc::new(MutationGate::new(16));
            {
                let gate_for_signal = gate.clone();
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        eprintln!("\n⏸ Pausing... waiting for active mutations...");
                        gate_for_signal.close_and_drain().await;
                    }
                });
            }

            let outcome = crate::teardown::workflow::resume_from_journal(
                client,
                config,
                j,
                journal_path,
                &gate,
                refresh_discovery,
            )
            .await?;
            crate::teardown::workflow::require_completed(&outcome)?;
        }
        TeardownAction::Batch {
            config: config_path,
            refresh_discovery,
            dry_run,
            skip_missing,
            backup_dir,
        } => {
            let no_cache = refresh_discovery;
            let config_content = std::fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config: {}", config_path))?;
            let parsed: ApplySetConfig = serde_json::from_str(&config_content)
                .with_context(|| format!("Invalid config: {}", config_path))?;
            let defaults = parsed.defaults;
            let entries = parsed.operators;

            if entries.is_empty() {
                bail!("Config has no operators");
            }
            for (i, entry) in entries.iter().enumerate() {
                if entry.name.is_empty() {
                    bail!("Operator entry {} has empty name", i);
                }
            }

            eprintln!(
                "📋 Batch: {} operator(s) from {}",
                entries.len(),
                config_path
            );
            for (i, entry) in entries.iter().enumerate() {
                let dr_count = entry.delete_resources.len();
                let suffix = if dr_count > 0 {
                    format!(" (+{} explicit)", dr_count)
                } else {
                    String::new()
                };
                eprintln!("  {}: {}{}", i + 1, entry.name, suffix);
            }
            eprintln!();

            // Setup backup dir if specified
            if let Some(ref bdir) = backup_dir {
                if bdir.is_empty() {
                    bail!("--backup-dir path must not be empty");
                }
                crate::teardown::backup::setup_backup_dir(std::path::Path::new(bdir))?;
                eprintln!("📦 Backup dir: {}", bdir);
            }

            // Baseline gate: verify all target operators are present (phase is informational)
            eprintln!(
                "🔍 Baseline gate: verifying {} target operators...",
                entries.len()
            );
            let (kind_map, _, _, _) = build_kind_lookup_cached(client, config, true).await?;
            let all_operators = discover_operators(client, &kind_map).await?;
            let cluster_id = journal::fetch_cluster_identity(client).await?;
            use crate::teardown::workflow::BaselineObservation;
            let mut observations: Vec<(String, BaselineObservation)> = Vec::new();
            for entry in &entries {
                let found = all_operators
                    .iter()
                    .find(|op| operator_matches_entry(op, &entry.name));
                match found {
                    Some(op) => {
                        let icon = if op.csv_phase == "Succeeded" {
                            "✅"
                        } else {
                            "⚠"
                        };
                        eprintln!(
                            "  {} {} — {} ({})",
                            icon, entry.name, op.csv.name, op.csv_phase
                        );
                        observations.push((entry.name.clone(), BaselineObservation::Present));
                    }
                    None => {
                        let pending_run =
                            find_pending_explicit_cleanup_journal(&cluster_id, &entry.name)?;
                        if let Some(ref run_id) = pending_run {
                            eprintln!(
                                "  🔄 {} — absent but has pending explicit cleanup ({})",
                                entry.name, run_id
                            );
                            observations.push((
                                entry.name.clone(),
                                BaselineObservation::PendingResume {
                                    run_id: run_id.clone(),
                                },
                            ));
                        } else if skip_missing {
                            eprintln!("  ⏭ {} — not found, will skip", entry.name);
                            observations.push((entry.name.clone(), BaselineObservation::Missing));
                        } else {
                            eprintln!("  ⛔ {} — NOT FOUND", entry.name);
                            observations.push((entry.name.clone(), BaselineObservation::Missing));
                        }
                    }
                }
            }
            if no_cache {
                eprintln!("🔄 API discovery: refresh once, then reuse within this batch\n");
            }

            // Classify entries — baseline gate enforced inside classify
            let classified = crate::teardown::workflow::classify_batch_entries(
                &observations,
                skip_missing,
                dry_run,
            )?;

            let present_count = classified
                .iter()
                .filter(|e| {
                    matches!(
                        e.kind,
                        crate::teardown::workflow::BatchEntryKind::PlanAndApply
                    )
                })
                .count();
            let skip_count = classified
                .iter()
                .filter(|e| matches!(e.kind, crate::teardown::workflow::BatchEntryKind::Skip))
                .count();
            let resume_count = classified
                .iter()
                .filter(|e| {
                    matches!(
                        e.kind,
                        crate::teardown::workflow::BatchEntryKind::PendingResume { .. }
                            | crate::teardown::workflow::BatchEntryKind::DryRunResume { .. }
                    )
                })
                .count();
            eprintln!(
                "✅ Baseline: {}/{} operators present{}{}\n",
                present_count,
                entries.len(),
                if skip_count > 0 {
                    format!(", {} skipped", skip_count)
                } else {
                    String::new()
                },
                if resume_count > 0 {
                    format!(", {} pending resume", resume_count)
                } else {
                    String::new()
                },
            );

            // Shared gate for entire batch — Ctrl-C stops all remaining entries
            let batch_gate = std::sync::Arc::new(MutationGate::new(16));
            if !dry_run {
                let gate_for_signal = batch_gate.clone();
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        eprintln!("\n⏸ Pausing... waiting for active mutations to complete...");
                        gate_for_signal.close_and_drain().await;
                    }
                });
            }

            let entry_count = entries.len();

            let effective_defaults = &defaults;
            let results = crate::teardown::workflow::run_batch_entries(
                &classified,
                &batch_gate,
                |source_index, op_name| {
                    let op_name = op_name.to_string();
                    let client = &client;
                    let config = &config;
                    let entries = &entries;
                    let defaults = effective_defaults;
                    let backup_dir_ref = backup_dir.as_deref();
                    let batch_gate = &batch_gate;
                    async move {
                        let entry = &entries[source_index];
                        let options = entry.effective_options(defaults);
                        eprintln!(
                            "\n{}\n  {} {}\n{}",
                            "=".repeat(60),
                            if dry_run { "DRY-RUN" } else { "TEARDOWN" },
                            op_name,
                            "=".repeat(60),
                        );
                        let gen_params = crate::teardown::workflow::GeneratePlanParams {
                            operator_name: &op_name,
                            approve_delete: &options.approve_delete,
                            preserve: &options.preserve,
                            delete_resources: &options.delete_resources,
                            refresh_discovery: apply_set_child_bypasses_cache(
                                no_cache,
                                source_index,
                            ),
                        };
                        let exec_plan =
                            crate::teardown::workflow::generate_execution_plan_for_operator(
                                client,
                                config,
                                &gen_params,
                            )
                            .await?;
                        let apply_params = crate::teardown::workflow::ApplyParams {
                            dry_run,
                            backup_dir: backup_dir_ref,
                            skip_confirm: true,
                            refresh_discovery: false,
                            gate: batch_gate,
                        };
                        crate::teardown::workflow::apply_execution_plan(
                            client,
                            config,
                            &exec_plan,
                            &apply_params,
                        )
                        .await
                    }
                },
                |run_id| {
                    let run_id = run_id.to_string();
                    let client = &client;
                    let config = &config;
                    let batch_gate = &batch_gate;
                    let cluster_id = &cluster_id;
                    async move {
                        let resume_path = journal::run_path(cluster_id, &run_id)?;
                        let resume_j = journal::load_journal(&resume_path)?;
                        crate::teardown::workflow::resume_from_journal(
                            client,
                            config,
                            resume_j,
                            resume_path,
                            batch_gate,
                            no_cache,
                        )
                        .await
                    }
                },
            )
            .await;

            // Summary
            let (s, sk, f) = batch_summary(&results);
            eprintln!("\n📊 Batch results:");
            let mut any_failed = false;
            let mut not_run = 0usize;
            for (name, outcome) in &results {
                match outcome {
                    BatchOutcome::Succeeded => eprintln!("  ✅ {}", name),
                    BatchOutcome::Skipped => eprintln!("  ⏭ {} SKIPPED", name),
                    BatchOutcome::Failed(c) => {
                        eprintln!("  ⛔ {} (exit {})", name, c);
                        any_failed = true;
                    }
                    BatchOutcome::NotRun => {
                        not_run += 1;
                    }
                }
            }
            let unrecorded = entry_count.saturating_sub(results.len());
            not_run += unrecorded;
            if not_run > 0 {
                eprintln!("  ⏭ {} operator(s) not run (stopped on failure)", not_run);
            }
            eprintln!(
                "\n  {} succeeded, {} skipped, {} failed, {} not run",
                s, sk, f, not_run
            );

            if any_failed {
                std::process::exit(1);
            }
        }
        TeardownAction::Runs => {
            let cluster_id = journal::fetch_cluster_identity(client).await?;
            let runs = journal::list_runs(&cluster_id)?;
            if runs.is_empty() {
                eprintln!("No teardown runs found for this cluster.");
            } else {
                eprintln!(
                    "Teardown runs for cluster {}:\n",
                    cluster_id.kube_system_uid
                );
                for run in &runs {
                    eprintln!(
                        "  {} {} {:?} ({})",
                        run.run_id, run.operator.csv_name, run.state, run.created_at,
                    );
                }
            }
        }
        TeardownAction::Journal {
            operator,
            run,
            no_audit,
            output,
        } => {
            let cluster_id = journal::fetch_cluster_identity(client).await?;

            let found = if let Some(run_id) = run {
                let path = journal::run_path(&cluster_id, &run_id)?;
                Some(journal::load_journal(&path)?)
            } else if let Some(op) = operator {
                journal::find_latest_run(&cluster_id, &op)?
            } else {
                bail!("Specify an operator name or --run <run-id>");
            };

            match found {
                Some(j) => {
                    use crate::teardown::audit::{
                        self, OperatorGenerationState, print_residual_audit,
                    };

                    print_run_journal(&j);

                    if no_audit {
                        eprintln!("\n(audit skipped via --no-audit)");
                    } else {
                        let gen_state = audit::check_operator_generation_fresh(
                            client,
                            &j.operator,
                            &j.audit_context.csv_baseline,
                        )
                        .await;

                        match gen_state {
                            OperatorGenerationState::Absent => {
                                eprintln!("\n🔍 Running live residual audit...");
                                match crate::teardown::audit::run_observed_audit(client, &j).await {
                                    Ok(result) => {
                                        match output {
                                            crate::cli::OutputFormat::Json => {
                                                println!(
                                                    "{}",
                                                    audit::format_residual_audit_json(&result)
                                                );
                                            }
                                            crate::cli::OutputFormat::Table => {
                                                audit::format_residual_audit_table(&result, &j);
                                            }
                                            crate::cli::OutputFormat::Tree => {
                                                print_residual_audit(&result, &j);
                                            }
                                        }
                                        // teardown journal is read-only — audit results are
                                        // displayed but NOT persisted to the journal file.
                                        // Cross-process journal writes require PR3's full
                                        // exclusive lock design.
                                    }
                                    Err(e) => {
                                        eprintln!("\n⚠ Residual audit failed: {}", e);
                                    }
                                }
                            }
                            OperatorGenerationState::SameGeneration => {
                                eprintln!("\n⚠ Original operator generation is still active.");
                                eprintln!("  Resume normal teardown instead of residual cleanup.");
                            }
                            OperatorGenerationState::Reappeared => {
                                eprintln!(
                                    "\n⚠ A newer installation of {} exists.",
                                    j.operator.csv_name
                                );
                                eprintln!("  This teardown session is historical.");
                                eprintln!("  Live residual attribution is unavailable because");
                                eprintln!(
                                    "  old and new generation resources cannot be distinguished safely."
                                );
                                if let Some(ref last_audit) = j.last_residual_audit {
                                    eprintln!("\n  Last reliable residual audit:");
                                    print_residual_audit(last_audit, &j);
                                }
                            }
                            OperatorGenerationState::Unknown(reason) => {
                                eprintln!("\n⚠ Cannot verify operator generation: {}", reason);
                                eprintln!("  Residual audit and cleanup are blocked.");
                            }
                        }
                    }
                }
                None => {
                    eprintln!("No teardown run found.");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod basis_drift_tests {
    use super::*;
    use crate::teardown::plan::*;
    use crate::teardown::workflow::{
        ExplicitCleanupResumeMode, ResumeStage, classify_resume_stage,
        explicit_cleanup_resume_mode, select_pending_explicit_cleanup_journal,
    };
    #[test]
    fn apply_set_no_cache_only_refreshes_first_entry() {
        assert!(apply_set_child_bypasses_cache(true, 0));
        assert!(!apply_set_child_bypasses_cache(true, 1));
        assert!(!apply_set_child_bypasses_cache(false, 0));
    }

    #[test]
    fn structured_apply_set_approvals_separate_scopes_and_resources() {
        let config: ApplySetConfig = serde_json::from_str(
            r#"{
                "operators": [{
                    "name": "example-operator",
                    "approve_delete": {
                        "scopes": ["root", "independent", "label-only", "operator-group"],
                        "resources": ["example.io/Widget/ns/example"]
                    }
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(
            config.operators[0].approve_delete.cli_args(),
            vec![
                "root",
                "independent",
                "label-only",
                "operator-group",
                "example.io/Widget/ns/example",
            ]
        );
    }

    #[test]
    fn apply_set_defaults_are_merged_with_operator_exceptions() {
        let config: ApplySetConfig = serde_json::from_str(
            r#"{
                "defaults": {
                    "approve_delete": {
                        "scopes": ["root", "independent", "label-only", "operator-group"]
                    }
                },
                "operators": [{
                    "name": "example-operator",
                    "approve_delete": {
                        "resources": ["example.io/Widget/ns/example"]
                    }
                }]
            }"#,
        )
        .unwrap();

        let options = config.operators[0].effective_options(&config.defaults);
        assert_eq!(
            options.approve_delete,
            vec![
                "root",
                "independent",
                "label-only",
                "operator-group",
                "example.io/Widget/ns/example",
            ]
        );
    }

    #[test]
    fn batch_config_rejects_force_field() {
        let result = serde_json::from_str::<ApplySetConfig>(
            r#"{
                "defaults": { "force": true },
                "operators": [{ "name": "example-operator" }]
            }"#,
        );
        assert!(
            result.is_err(),
            "force field must be rejected by deny_unknown_fields"
        );
    }

    #[test]
    fn structured_apply_set_approvals_reject_all_scope() {
        let result = serde_json::from_str::<ApplySetConfig>(
            r#"{
                "operators": [{
                    "name": "example-operator",
                    "approve_delete": { "scopes": ["all"] }
                }]
            }"#,
        );
        assert!(result.is_err(), "structured scopes must be explicit");
    }

    #[test]
    fn legacy_apply_set_approval_array_rejected() {
        let result: Result<ApplySetConfig, _> = serde_json::from_str(
            r#"{
                "operators": [{
                    "name": "example-operator",
                    "approve_delete": ["all", "Widget/example"]
                }]
            }"#,
        );
        assert!(
            result.is_err(),
            "Legacy array form must be rejected (use structured scopes/resources)"
        );
    }

    // ── Multi-seed MVP restriction ──

    // ── Resume stage + crash recovery tests (call extracted functions) ──

    fn make_test_journal(
        state: crate::teardown::journal::RunState,
        phases_completed: usize,
        phases_total: usize,
        has_audit: bool,
        decisions: Vec<crate::teardown::journal::CleanupDecision>,
    ) -> crate::teardown::journal::RunJournal {
        use crate::teardown::journal::*;
        use crate::teardown::plan::*;
        use crate::teardown::planner::*;
        RunJournal {
            run_id: "test-run".to_string(),
            schema_version: RUN_JOURNAL_SCHEMA_VERSION,
            oc_deps_version: "0.1.0".to_string(),
            journal_revision: 0,
            cluster_identity: ClusterIdentity {
                api_server: "https://test:6443".to_string(),
                kube_system_uid: "test-uid".to_string(),
            },
            operator: OperatorIdentitySnapshot {
                generation_identity: OperatorGenerationIdentity::Unverifiable {
                    reason: "test".to_string(),
                },
                operator_id: crate::analyzers::olm::OperatorId {
                    namespace: "ns".to_string(),
                    csv_name: "test.1.0".to_string(),
                },
                csv_name: "test.1.0".to_string(),
                csv: ObservedResourceIdentity {
                    resource: crate::kube::resource::ResourceId {
                        group: "operators.coreos.com".to_string(),
                        version: "v1alpha1".to_string(),
                        kind: "ClusterServiceVersion".to_string(),
                        namespace: Some("ns".to_string()),
                        name: "test.1.0".to_string(),
                        uid: Some("csv-uid".to_string()),
                    },
                    uid: "csv-uid".to_string(),
                },
                subscriptions: vec![],
                controller_deployments: vec![],
                service_accounts: vec![],
                owned_crds: vec![],
                required_crds: vec![],
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            state,
            residual_status: if has_audit {
                ResidualStatus::NoneObservedInScope
            } else {
                ResidualStatus::NotAudited
            },
            audit_revision: 0,
            audit_context: AuditContext::default(),
            plan_snapshot: TeardownPlan {
                targets: vec![],
                preflight: Preflight { checks: vec![] },
                phases: vec![],
                blockers: vec![],
                warnings: vec![],
                snapshot_taken_at: "2026-01-01T00:00:00Z".to_string(),
                dependency_edges: vec![],
                operator_inventory: vec![],
                explicit_decisions: vec![],
                explicit_deletes: vec![],
            },
            execution: ExecutionRecord {
                phases_completed,
                phases_total,
                ..Default::default()
            },
            last_residual_audit: if has_audit {
                Some(crate::teardown::audit::ResidualAudit {
                    planned_delete_still_present: vec![],
                    planned_expect_still_present: vec![],
                    expected_preserved: vec![],
                    likely_operator_residual: vec![],
                    unattributed: vec![],
                    coverage: crate::teardown::audit::AuditCoverage {
                        requested_probes: 0,
                        succeeded_probes: 0,
                    },
                    scan_errors: vec![],
                    target_operators_absent: false,
                    residual_workloads: Vec::new(),
                    incomplete_scopes: Vec::new(),
                })
            } else {
                None
            },
            cleanup_decisions: decisions,
            finalizer_recovery_approved: false,
            finalizer_recoveries: Vec::new(),
            backup_receipts: vec![],
        }
    }

    fn make_decision(
        name: &str,
        result: Option<crate::teardown::journal::CleanupResult>,
    ) -> crate::teardown::journal::CleanupDecision {
        crate::teardown::journal::CleanupDecision {
            resource: crate::kube::resource::ResourceId {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string(),
                namespace: Some("ns".to_string()),
                name: name.to_string(),
                uid: Some(format!("uid-{}", name)),
            },
            bound_uid: Some(format!("uid-{}", name)),
            action: "delete".to_string(),
            result,
            approved_spec_name: None,
        }
    }

    #[test]
    fn classify_resume_paused_from_residual_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::Paused, 7, 7, true, vec![]);
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::Cleanup);
    }

    #[test]
    fn classify_resume_paused_from_main_routes_to_execution() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::Paused, 3, 7, false, vec![]);
        assert_eq!(
            classify_resume_stage(&j).unwrap(),
            ResumeStage::MainExecution
        );
    }

    #[test]
    fn classify_resume_interactive_cleanup_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::InteractiveCleanup, 7, 7, true, vec![]);
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::Cleanup);
    }

    #[test]
    fn classify_resume_paused_with_pending_complete_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(
            RunState::Paused,
            7,
            7,
            false,
            vec![make_decision("a", None)],
        );
        assert_eq!(classify_resume_stage(&j).unwrap(), ResumeStage::Cleanup);
    }

    #[test]
    fn classify_resume_pending_with_incomplete_phases_is_error() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(
            RunState::Paused,
            5,
            7,
            false,
            vec![make_decision("a", None)],
        );
        assert!(
            classify_resume_stage(&j).is_err(),
            "Pending cleanup with incomplete main phases = inconsistent journal"
        );
    }

    #[test]
    fn classify_resume_interactive_cleanup_incomplete_phases_is_error() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::InteractiveCleanup, 3, 7, true, vec![]);
        assert!(
            classify_resume_stage(&j).is_err(),
            "InteractiveCleanup with incomplete phases = inconsistent journal"
        );
    }

    #[test]
    fn classify_resume_apply_completed_no_audit_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::ApplyCompleted, 7, 7, false, vec![]);
        assert_eq!(
            classify_resume_stage(&j).unwrap(),
            ResumeStage::Cleanup,
            "ApplyCompleted with no audit = crash recovery → cleanup branch"
        );
    }

    #[test]
    fn classify_resume_apply_completed_with_audit_routes_to_cleanup() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::ApplyCompleted, 7, 7, true, vec![]);
        assert_eq!(
            classify_resume_stage(&j).unwrap(),
            ResumeStage::Cleanup,
            "ApplyCompleted + audit + complete = Residual re-entry"
        );
    }

    // ── PatchRequested resume block ──

    #[test]
    fn classify_resume_blocks_on_unresolved_patch_requested() {
        use crate::teardown::journal::{
            FinalizerRecoveryRecord, FinalizerRecoveryResult, OwnerRefSnapshot, RunState,
        };
        let mut j = make_test_journal(RunState::Paused, 3, 7, false, vec![]);
        j.finalizer_recoveries.push(FinalizerRecoveryRecord {
            resource: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
                uid: Some("uid-w1".to_string()),
            },
            live_uid: "uid-w1".to_string(),
            finalizer_values: vec!["test/fin".to_string()],
            owner_references_snapshot: vec![OwnerRefSnapshot {
                api_version: "v1".to_string(),
                kind: "Parent".to_string(),
                name: "p1".to_string(),
                uid: "uid-p1".to_string(),
                controller: Some(true),
            }],
            root_uid: "uid-p1".to_string(),
            root_kind: "Parent".to_string(),
            result: FinalizerRecoveryResult::PatchRequested,
        });
        let err = classify_resume_stage(&j).unwrap_err();
        assert!(
            err.contains("PatchRequested"),
            "Should block on PatchRequested: {}",
            err
        );
    }

    #[test]
    fn classify_resume_allows_resolved_recovery() {
        use crate::teardown::journal::{
            FinalizerRecoveryRecord, FinalizerRecoveryResult, OwnerRefSnapshot, RunState,
        };
        let mut j = make_test_journal(RunState::Paused, 3, 7, false, vec![]);
        j.finalizer_recoveries.push(FinalizerRecoveryRecord {
            resource: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
                uid: Some("uid-w1".to_string()),
            },
            live_uid: "uid-w1".to_string(),
            finalizer_values: vec!["test/fin".to_string()],
            owner_references_snapshot: vec![OwnerRefSnapshot {
                api_version: "v1".to_string(),
                kind: "Parent".to_string(),
                name: "p1".to_string(),
                uid: "uid-p1".to_string(),
                controller: Some(true),
            }],
            root_uid: "uid-p1".to_string(),
            root_kind: "Parent".to_string(),
            result: FinalizerRecoveryResult::Stripped,
        });
        assert!(
            classify_resume_stage(&j).is_ok(),
            "Resolved recovery (Stripped) should not block resume"
        );
    }

    // ── ExplicitCleanupBlocked resume tests ──

    fn make_explicit_cleanup_journal(
        state: crate::teardown::journal::RunState,
        phases_completed: usize,
        cleanup_error: Option<crate::teardown::journal::ExplicitCleanupError>,
    ) -> crate::teardown::journal::RunJournal {
        use crate::teardown::plan::*;
        use crate::teardown::planner::*;
        let mut j = make_test_journal(state, phases_completed, 8, false, vec![]);
        j.plan_snapshot.explicit_deletes = vec![ExplicitDeleteTarget {
            group: "apps".to_string(),
            kind: "Deployment".to_string(),
            namespace: Some("ns".to_string()),
            name: "target-deploy".to_string(),
            uid: "uid-1".to_string(),
            reason: "explicit".to_string(),
            inbound_refs_at_plan: vec![],
            ref_scan_coverage: RefScanCoverage {
                kinds_scanned: vec![],
                scan_complete: true,
            },
        }];
        j.plan_snapshot.phases = vec![
            PlanPhase {
                name: "Freeze OLM".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: "Trigger operand cleanup".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: "Remaining cleanup".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: "Remove Operator controllers".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: "Namespace cleanup".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: EXPLICIT_CLEANUP_PHASE_NAME.to_string(),
                description: "test".to_string(),
                actions: vec![Action::Delete {
                    resource: crate::kube::resource::ResourceId {
                        group: "apps".to_string(),
                        version: "v1".to_string(),
                        kind: "Deployment".to_string(),
                        namespace: Some("ns".to_string()),
                        name: "target-deploy".to_string(),
                        uid: Some("uid-1".to_string()),
                    },
                    reason: "explicit".to_string(),
                }],
                barrier: None,
            },
            PlanPhase {
                name: "APIs".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
            PlanPhase {
                name: "Namespaces".to_string(),
                description: "test".to_string(),
                actions: vec![],
                barrier: None,
            },
        ];
        j.execution.explicit_cleanup_error = cleanup_error;
        j
    }

    #[test]
    fn classify_resume_explicit_cleanup_blocked_routes_to_main() {
        use crate::teardown::journal::{ExplicitCleanupError, ExplicitCleanupErrorKind, RunState};
        let j = make_explicit_cleanup_journal(
            RunState::ExplicitCleanupBlocked,
            5,
            Some(ExplicitCleanupError {
                target: "Deployment/target-deploy".to_string(),
                error_kind: ExplicitCleanupErrorKind::IncompleteScan,
                message: "ref scan incomplete".to_string(),
            }),
        );
        let stage = classify_resume_stage(&j).expect("should be resumable");
        assert_eq!(stage, ResumeStage::MainExecution);
    }

    #[test]
    fn classify_resume_explicit_cleanup_blocked_no_explicit_deletes_is_error() {
        use crate::teardown::journal::RunState;
        let mut j = make_explicit_cleanup_journal(RunState::ExplicitCleanupBlocked, 5, None);
        j.plan_snapshot.explicit_deletes.clear();
        let result = classify_resume_stage(&j);
        assert!(result.is_err(), "should reject without explicit_deletes");
    }

    #[test]
    fn classify_resume_explicit_cleanup_blocked_wrong_phase_is_error() {
        use crate::teardown::journal::RunState;
        // phases_completed=3 → next phase is "Remove Operator controllers", not Explicit cleanup
        let j = make_explicit_cleanup_journal(RunState::ExplicitCleanupBlocked, 3, None);
        let result = classify_resume_stage(&j);
        assert!(
            result.is_err(),
            "should reject when next phase is not Explicit cleanup"
        );
    }

    #[test]
    fn classify_resume_generic_failed_remains_non_resumable() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::Failed, 5, 8, false, vec![]);
        let err = classify_resume_stage(&j).unwrap_err();
        assert!(
            err.contains("phase count mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn legacy_failed_exact_explicit_boundary_is_narrowly_eligible() {
        use crate::teardown::backup::BackupReceipt;
        use crate::teardown::journal::RunState;
        let mut j = make_explicit_cleanup_journal(RunState::Failed, 5, None);
        j.backup_receipts.push(BackupReceipt {
            root: "/tmp/test-backup".to_string(),
            manifest_sha256: "manifest".to_string(),
            tree_sha256: "tree".to_string(),
            resource_set_sha256: "resources".to_string(),
            resource_count: 1,
            contains_secret_data: false,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        });
        assert_eq!(
            explicit_cleanup_resume_mode(&j).unwrap(),
            ExplicitCleanupResumeMode::LegacyFailed
        );
        assert_eq!(
            classify_resume_stage(&j).unwrap(),
            ResumeStage::MainExecution
        );
    }

    #[test]
    fn legacy_failed_without_backup_is_not_migrated() {
        use crate::teardown::journal::RunState;
        let j = make_explicit_cleanup_journal(RunState::Failed, 5, None);
        let err = explicit_cleanup_resume_mode(&j).unwrap_err();
        assert!(err.contains("backup receipt"));
    }

    #[test]
    fn batch_selection_delegates_eligible_legacy_failed_journal() {
        use crate::teardown::backup::BackupReceipt;
        use crate::teardown::journal::RunState;
        let mut j = make_explicit_cleanup_journal(RunState::Failed, 5, None);
        j.run_id = "retry4".to_string();
        j.backup_receipts.push(BackupReceipt {
            root: "/tmp/test-backup".to_string(),
            manifest_sha256: "manifest".to_string(),
            tree_sha256: "tree".to_string(),
            resource_set_sha256: "resources".to_string(),
            resource_count: 1,
            contains_secret_data: false,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        });
        assert_eq!(
            select_pending_explicit_cleanup_journal(&[j], "test").unwrap(),
            Some("retry4".to_string())
        );
    }

    #[test]
    fn batch_selection_rejects_ineligible_latest_explicit_journal() {
        use crate::teardown::journal::RunState;
        let mut j = make_explicit_cleanup_journal(RunState::Failed, 5, None);
        j.run_id = "unsafe".to_string();
        let err = select_pending_explicit_cleanup_journal(&[j], "test").unwrap_err();
        assert!(err.contains("not safely resumable"));
        assert!(err.contains("backup receipt"));
    }

    #[test]
    fn batch_dry_run_classifies_pending_as_dry_run_resume() {
        use crate::teardown::workflow::{
            BaselineObservation, BatchEntryKind, classify_batch_entries,
        };
        let entries = vec![(
            "op-a".to_string(),
            BaselineObservation::PendingResume {
                run_id: "run-123".to_string(),
            },
        )];
        let classified = classify_batch_entries(&entries, true, true).unwrap();
        assert!(
            matches!(&classified[0].kind, BatchEntryKind::DryRunResume { run_id } if run_id == "run-123"),
            "dry_run pending resume → DryRunResume"
        );
        let classified_live = classify_batch_entries(&entries, true, false).unwrap();
        assert!(
            matches!(&classified_live[0].kind, BatchEntryKind::PendingResume { run_id } if run_id == "run-123"),
            "non-dry_run pending resume → PendingResume"
        );
    }

    #[test]
    fn explicit_cleanup_resume_rejects_prior_target_outcome() {
        use crate::teardown::journal::{ExplicitCleanupError, ExplicitCleanupErrorKind, RunState};
        let mut j = make_explicit_cleanup_journal(
            RunState::ExplicitCleanupBlocked,
            5,
            Some(ExplicitCleanupError {
                target: "Deployment/target-deploy".to_string(),
                error_kind: ExplicitCleanupErrorKind::IncompleteScan,
                message: "incomplete".to_string(),
            }),
        );
        let target = match &j.plan_snapshot.phases[5].actions[0] {
            crate::teardown::planner::Action::Delete { resource, .. } => resource.clone(),
            _ => unreachable!(),
        };
        j.execution.deleted.push(target);
        let err = explicit_cleanup_resume_mode(&j).unwrap_err();
        assert!(err.contains("mutation outcome"));
    }

    #[test]
    fn explicit_cleanup_resume_rejects_metadata_action_mismatch() {
        use crate::teardown::journal::{ExplicitCleanupError, ExplicitCleanupErrorKind, RunState};
        let mut j = make_explicit_cleanup_journal(
            RunState::ExplicitCleanupBlocked,
            5,
            Some(ExplicitCleanupError {
                target: "Deployment/target-deploy".to_string(),
                error_kind: ExplicitCleanupErrorKind::IncompleteScan,
                message: "incomplete".to_string(),
            }),
        );
        j.plan_snapshot.explicit_deletes[0].uid = "different-uid".to_string();
        let err = explicit_cleanup_resume_mode(&j).unwrap_err();
        assert!(err.contains("1:1"));
    }

    #[test]
    fn explicit_guard_transient_timeout_classifies_correctly() {
        use crate::kube::resource::ScanWarning;
        use crate::teardown::executor::ExplicitGuardOutcome;
        let w = ScanWarning::Timeout {
            gvr: "v1/pods".to_string(),
            message: Some("timeout".to_string()),
            retries: 2,
        };
        let outcome = ExplicitGuardOutcome::from_scan_warning(&w, "Deployment/test");
        assert!(matches!(outcome, ExplicitGuardOutcome::TransientFailure(_)));
        if let ExplicitGuardOutcome::TransientFailure(err) = outcome {
            assert_eq!(
                err.error_kind,
                crate::teardown::journal::ExplicitCleanupErrorKind::Timeout
            );
        }
    }

    #[test]
    fn explicit_guard_forbidden_classifies_transient() {
        use crate::kube::resource::ScanWarning;
        use crate::teardown::executor::ExplicitGuardOutcome;
        let w = ScanWarning::Forbidden {
            gvr: "apps/v1/deployments".to_string(),
            status: 403,
        };
        let outcome = ExplicitGuardOutcome::from_scan_warning(&w, "Deployment/test");
        assert!(matches!(outcome, ExplicitGuardOutcome::TransientFailure(_)));
        if let ExplicitGuardOutcome::TransientFailure(err) = outcome {
            assert_eq!(
                err.error_kind,
                crate::teardown::journal::ExplicitCleanupErrorKind::Forbidden
            );
        }
    }

    #[test]
    fn explicit_guard_server_error_classifies_transient() {
        use crate::kube::resource::ScanWarning;
        use crate::teardown::executor::ExplicitGuardOutcome;
        let w = ScanWarning::ServerError {
            gvr: "v1/pods".to_string(),
            status: 500,
            message: "internal".to_string(),
            retries: 3,
        };
        let outcome = ExplicitGuardOutcome::from_scan_warning(&w, "Deployment/test");
        assert!(matches!(outcome, ExplicitGuardOutcome::TransientFailure(_)));
        if let ExplicitGuardOutcome::TransientFailure(err) = outcome {
            assert_eq!(
                err.error_kind,
                crate::teardown::journal::ExplicitCleanupErrorKind::ServerError
            );
        }
    }

    #[test]
    fn explicit_guard_other_error_classifies_hard() {
        use crate::kube::resource::ScanWarning;
        use crate::teardown::executor::ExplicitGuardOutcome;
        let w = ScanWarning::Other {
            gvr: "v1/pods".to_string(),
            message: "something weird".to_string(),
        };
        let outcome = ExplicitGuardOutcome::from_scan_warning(&w, "Deployment/test");
        assert!(matches!(outcome, ExplicitGuardOutcome::HardFailure(_)));
    }

    #[test]
    fn executor_error_checkpoint_preserves_only_typed_retryable_state() {
        use crate::teardown::journal::{RunState, mark_failed_preserving_retryable};
        let mut blocked = make_explicit_cleanup_journal(
            RunState::ExplicitCleanupBlocked,
            5,
            Some(crate::teardown::journal::ExplicitCleanupError {
                target: "Deployment/target-deploy".to_string(),
                error_kind: crate::teardown::journal::ExplicitCleanupErrorKind::IncompleteScan,
                message: "incomplete".to_string(),
            }),
        );
        mark_failed_preserving_retryable(&mut blocked);
        assert_eq!(blocked.state, RunState::ExplicitCleanupBlocked);

        let mut applying = make_test_journal(RunState::Applying, 2, 8, false, vec![]);
        mark_failed_preserving_retryable(&mut applying);
        assert_eq!(applying.state, RunState::Failed);
    }

    // ── MVP safety boundary tests ──

    #[test]
    fn prepared_journal_rejects_resume_mutation() {
        use crate::teardown::journal::RunState;
        let j = make_test_journal(RunState::Prepared, 0, 7, false, vec![]);
        let result = classify_resume_stage(&j);
        assert!(result.is_err(), "Prepared journal must reject resume");
        assert!(
            result.unwrap_err().contains("Prepared"),
            "Error must mention Prepared state"
        );
    }

    #[test]
    fn expect_resources_do_not_create_re_delete_authority() {
        use crate::teardown::journal::{ReDeleteRecord, ReDeleteResult, RunState};
        let mut j = make_test_journal(RunState::Applying, 3, 7, false, vec![]);
        // Simulate: EXPECT descendant was observed as Gone, no re-delete authority
        // Re-delete authority can only come from explicit DELETE accepted+Gone+Recreated
        assert!(
            j.execution.re_delete_records.is_empty(),
            "Fresh journal must have no re-delete authority"
        );
        // Manually adding a record simulates executor behavior
        j.execution.re_delete_records.push(ReDeleteRecord {
            resource_identity: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Widget".to_string(),
                namespace: Some("ns".to_string()),
                name: "w1".to_string(),
                uid: None,
            },
            original_uid: "uid-orig".to_string(),
            new_uid: "uid-new".to_string(),
            result: ReDeleteResult::Authorized,
        });
        // Authority exists — this is valid only if original DELETE was accepted+Gone
        assert_eq!(j.execution.re_delete_records.len(), 1);
        assert_eq!(
            j.execution.re_delete_records[0].result,
            ReDeleteResult::Authorized
        );
    }

    #[test]
    fn unresolved_redelete_blocks_resume() {
        use crate::teardown::journal::{ReDeleteRecord, ReDeleteResult, RunState};
        // MVP: any Authorized/Accepted/Unknown re-delete blocks resume
        for (variant, label) in [
            (ReDeleteResult::Authorized, "Authorized must block resume"),
            (ReDeleteResult::Accepted, "Accepted must block resume"),
            (
                ReDeleteResult::UnknownOutcome("500".to_string()),
                "Unknown must block resume",
            ),
        ] {
            let mut j = make_test_journal(RunState::Paused, 3, 7, false, vec![]);
            j.execution.re_delete_records.push(ReDeleteRecord {
                resource_identity: crate::kube::resource::ResourceId {
                    group: "test".to_string(),
                    version: "v1".to_string(),
                    kind: "Widget".to_string(),
                    namespace: None,
                    name: "w1".to_string(),
                    uid: None,
                },
                original_uid: "uid-old".to_string(),
                new_uid: "uid-new".to_string(),
                result: variant,
            });
            let result = classify_resume_stage(&j);
            assert!(result.is_err(), "{}", label);
            assert!(
                result.unwrap_err().contains("re-delete"),
                "Error must mention re-delete"
            );
        }
    }

    #[test]
    fn resolved_redelete_allows_resume() {
        use crate::teardown::journal::{ReDeleteRecord, ReDeleteResult, RunState};
        let mut j = make_test_journal(RunState::Paused, 3, 7, false, vec![]);
        j.execution.re_delete_records.push(ReDeleteRecord {
            resource_identity: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Widget".to_string(),
                namespace: None,
                name: "w1".to_string(),
                uid: None,
            },
            original_uid: "uid-old".to_string(),
            new_uid: "uid-new".to_string(),
            result: ReDeleteResult::Gone,
        });
        assert!(
            classify_resume_stage(&j).is_ok(),
            "Gone re-delete must allow resume"
        );
    }

    #[test]
    fn re_delete_record_roundtrip() {
        use crate::teardown::journal::{ReDeleteRecord, ReDeleteResult, RunState};
        let mut j = make_test_journal(RunState::Applying, 3, 7, false, vec![]);
        j.execution.re_delete_records.push(ReDeleteRecord {
            resource_identity: crate::kube::resource::ResourceId {
                group: "test".to_string(),
                version: "v1".to_string(),
                kind: "Auth".to_string(),
                namespace: None,
                name: "auth".to_string(),
                uid: None,
            },
            original_uid: "uid-orig".to_string(),
            new_uid: "uid-new".to_string(),
            result: ReDeleteResult::Gone,
        });
        let serialized = serde_json::to_string(&j).unwrap();
        let deser: crate::teardown::journal::RunJournal =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(deser.execution.re_delete_records.len(), 1);
        assert_eq!(
            deser.execution.re_delete_records[0].original_uid,
            "uid-orig"
        );
        assert_eq!(deser.execution.re_delete_records[0].new_uid, "uid-new");
        assert!(
            deser.execution.re_delete_records[0]
                .resource_identity
                .uid
                .is_none()
        );
    }

    #[test]
    fn delete_resource_spec_parse_core_group() {
        let spec = DeleteResourceSpec::parse_cli_arg("ConfigMap/ns-a/my-cm").unwrap();
        assert_eq!(spec.group, "");
        assert_eq!(spec.kind, "ConfigMap");
        assert_eq!(spec.namespace, Some("ns-a".to_string()));
        assert_eq!(spec.name, "my-cm");
    }

    #[test]
    fn delete_resource_spec_parse_with_group() {
        let spec =
            DeleteResourceSpec::parse_cli_arg("gateway.networking.k8s.io/Gateway/ns-a/my-gw")
                .unwrap();
        assert_eq!(spec.group, "gateway.networking.k8s.io");
        assert_eq!(spec.kind, "Gateway");
        assert_eq!(spec.namespace, Some("ns-a".to_string()));
        assert_eq!(spec.name, "my-gw");
    }

    #[test]
    fn delete_resource_spec_parse_cluster_scoped() {
        let spec =
            DeleteResourceSpec::parse_cli_arg("console.openshift.io/ConsolePlugin/-/my-plugin")
                .unwrap();
        assert_eq!(spec.group, "console.openshift.io");
        assert_eq!(spec.kind, "ConsolePlugin");
        assert_eq!(spec.namespace, None);
        assert_eq!(spec.name, "my-plugin");
    }

    #[test]
    fn delete_resource_spec_rejects_forbidden_kinds() {
        assert!(DeleteResourceSpec::parse_cli_arg("Namespace/-/my-ns").is_err());
        assert!(DeleteResourceSpec::parse_cli_arg("PersistentVolume/-/pv1").is_err());
        assert!(DeleteResourceSpec::parse_cli_arg("PersistentVolumeClaim/ns/pvc1").is_err());
        assert!(
            DeleteResourceSpec::parse_cli_arg(
                "apiextensions.k8s.io/CustomResourceDefinition/-/foo"
            )
            .is_err()
        );
        assert!(DeleteResourceSpec::parse_cli_arg("APIService/-/v1.foo").is_err());
    }

    #[test]
    fn delete_resource_spec_rejects_empty_fields() {
        assert!(DeleteResourceSpec::parse_cli_arg("/ns/name").is_err());
        assert!(DeleteResourceSpec::parse_cli_arg("ConfigMap/ns/").is_err());
    }

    #[test]
    fn delete_resource_spec_rejects_whitespace() {
        let spec = DeleteResourceSpec {
            group: "".into(),
            kind: " ConfigMap".into(),
            namespace: Some("ns".into()),
            name: "cm".into(),
        };
        assert!(spec.validate().is_err());

        let spec2 = DeleteResourceSpec {
            group: "".into(),
            kind: "ConfigMap".into(),
            namespace: Some("ns".into()),
            name: "cm ".into(),
        };
        assert!(spec2.validate().is_err());
    }

    #[test]
    fn batch_config_parses_delete_resources() {
        let config: ApplySetConfig = serde_json::from_str(
            r#"{
                "operators": [{
                    "name": "my-op",
                    "delete_resources": [
                        {"group": "apps", "kind": "Deployment", "namespace": "ns-a", "name": "my-deploy"},
                        {"group": "", "kind": "ConfigMap", "namespace": "ns-a", "name": "my-cm"}
                    ]
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(config.operators[0].delete_resources.len(), 2);
        assert_eq!(config.operators[0].delete_resources[0].kind, "Deployment");
        assert_eq!(config.operators[0].delete_resources[1].group, "");
    }

    #[test]
    fn batch_config_without_delete_resources_ok() {
        let config: ApplySetConfig = serde_json::from_str(
            r#"{
                "operators": [{"name": "my-op"}]
            }"#,
        )
        .unwrap();
        assert!(config.operators[0].delete_resources.is_empty());
    }

    #[test]
    fn inject_explicit_phase_errors_on_missing_gk() {
        use crate::teardown::plan::{ExplicitDeleteTarget, RefScanCoverage};
        use crate::teardown::planner::TeardownPlan;
        let mut plan = TeardownPlan {
            targets: vec![],
            preflight: crate::teardown::planner::Preflight { checks: vec![] },
            phases: vec![],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "".into(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
            explicit_deletes: vec![],
        };
        let targets = vec![ExplicitDeleteTarget {
            group: "nonexistent.io".into(),
            kind: "Widget".into(),
            namespace: Some("ns".into()),
            name: "w1".into(),
            uid: "uid-1".into(),
            reason: "config".into(),
            inbound_refs_at_plan: vec![],
            ref_scan_coverage: RefScanCoverage {
                kinds_scanned: vec![],
                scan_complete: true,
            },
        }];
        let gk_map = std::collections::HashMap::new();
        let result = inject_explicit_phase_into_teardown_plan(&mut plan, &targets, &gk_map);
        assert!(result.is_err(), "missing GK must error");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not found in API discovery"),
            "error should mention API discovery"
        );
    }

    #[test]
    fn should_refresh_discovery_logic() {
        assert!(
            !should_refresh_discovery(false, 0),
            "no flag, no targets = use cache"
        );
        assert!(
            should_refresh_discovery(true, 0),
            "user --refresh-discovery = refresh"
        );
        assert!(
            should_refresh_discovery(false, 1),
            "explicit targets present = force refresh even without flag"
        );
        assert!(
            should_refresh_discovery(true, 3),
            "both flag and targets = refresh"
        );
    }

    fn make_test_operator(
        csv_name: &str,
        phase: &str,
        pkg: Option<&str>,
    ) -> crate::analyzers::olm::OperatorInstance {
        crate::analyzers::olm::OperatorInstance {
            subscription: None,
            csv: crate::kube::resource::ResourceId {
                group: "operators.coreos.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "ClusterServiceVersion".to_string(),
                namespace: Some("test-ns".to_string()),
                name: csv_name.to_string(),
                uid: Some("test-uid".to_string()),
            },
            csv_phase: phase.to_string(),
            owned_crds: vec![],
            required_crds: vec![],
            owned_api_service_defs: vec![],
            required_api_service_defs: vec![],
            deployments: vec![],
            service_accounts: vec![],
            install_namespace: "test-ns".to_string(),
            package_name: pkg.map(|s| s.to_string()),
            has_unlinked_subscriptions: false,
        }
    }

    #[test]
    fn presence_gate_succeeded_passes() {
        let op = make_test_operator("rhods-operator.3.5.1", "Succeeded", Some("rhods-operator"));
        assert!(operator_matches_entry(&op, "rhods-operator"));
    }

    #[test]
    fn presence_gate_failed_passes() {
        let op = make_test_operator("rhods-operator.3.5.1", "Failed", Some("rhods-operator"));
        assert!(operator_matches_entry(&op, "rhods-operator"));
    }

    #[test]
    fn presence_gate_pending_passes() {
        let op = make_test_operator(
            "cert-manager-operator.v1.20.0",
            "Pending",
            Some("openshift-cert-manager-operator"),
        );
        assert!(operator_matches_entry(
            &op,
            "openshift-cert-manager-operator"
        ));
    }

    #[test]
    fn presence_gate_missing_fails() {
        let operators = [make_test_operator(
            "rhods-operator.3.5.1",
            "Succeeded",
            Some("rhods-operator"),
        )];
        let found = operators
            .iter()
            .any(|op| operator_matches_entry(op, "nonexistent-operator"));
        assert!(!found, "Missing operator must not match");
    }

    #[test]
    fn batch_summary_counts_outcomes_correctly() {
        let results = vec![
            ("op-a".to_string(), BatchOutcome::Succeeded),
            ("op-b".to_string(), BatchOutcome::Skipped),
            ("op-c".to_string(), BatchOutcome::Succeeded),
            ("op-d".to_string(), BatchOutcome::Failed(1)),
            ("op-e".to_string(), BatchOutcome::Skipped),
        ];
        let (s, sk, f) = batch_summary(&results);
        assert_eq!(s, 2, "succeeded count");
        assert_eq!(sk, 2, "skipped count");
        assert_eq!(f, 1, "failed count");
    }

    #[test]
    fn batch_skipped_excluded_from_success() {
        let results = vec![("op-a".to_string(), BatchOutcome::Skipped)];
        let (s, sk, f) = batch_summary(&results);
        assert_eq!(s, 0, "skipped must not count as succeeded");
        assert_eq!(sk, 1);
        assert_eq!(f, 0, "skipped must not count as failed");
    }

    #[test]
    fn health_preflight_produces_warning_not_critical() {
        use crate::teardown::planner::{PreflightSeverity, health_preflight_checks};
        let checks = health_preflight_checks(
            "test-op.v1",
            (false, "CSV phase: Failed".to_string()),
            (false, "0/1 controllers available".to_string()),
        );
        assert_eq!(checks.len(), 2);
        for check in &checks {
            assert_eq!(
                check.severity,
                PreflightSeverity::Warning,
                "{} must be Warning, not Critical",
                check.name
            );
            assert!(!check.passed);
        }
    }

    #[test]
    fn blocking_preflight_filters_critical_only() {
        use crate::teardown::executor::blocking_preflight_failures;
        use crate::teardown::planner::{PreflightCheck, PreflightSeverity};
        let checks = vec![
            PreflightCheck {
                name: "CSV health (op.v1)".to_string(),
                severity: PreflightSeverity::Warning,
                passed: false,
                detail: "Failed".to_string(),
            },
            PreflightCheck {
                name: "Controller available (op.v1)".to_string(),
                severity: PreflightSeverity::Warning,
                passed: false,
                detail: "unavailable".to_string(),
            },
            PreflightCheck {
                name: "CR enumeration (widgets)".to_string(),
                severity: PreflightSeverity::Critical,
                passed: false,
                detail: "cannot enumerate".to_string(),
            },
        ];
        let blockers = blocking_preflight_failures(&checks);
        assert_eq!(blockers.len(), 1, "only Critical should block");
        assert!(blockers[0].contains("CR enumeration"));
    }
}

#[cfg(test)]
mod resolve_explicit_target_tests {
    use super::*;
    use ::kube::client::Body;
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn json_response(json: serde_json::Value) -> http::Response<Body> {
        http::Response::builder()
            .status(200)
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap()
    }

    fn status_response(code: u16, reason: &str) -> http::Response<Body> {
        let body = serde_json::json!({
            "apiVersion": "v1", "kind": "Status",
            "metadata": {},
            "status": "Failure",
            "reason": reason,
            "code": code
        });
        http::Response::builder()
            .status(code)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn test_gk_map() -> crate::kube::discovery::GroupKindMap {
        let mut gk = std::collections::HashMap::new();
        let entries: Vec<(&str, &str, &str, &str)> = vec![
            ("", "ConfigMap", "v1", "configmaps"),
            ("apps", "Deployment", "v1", "deployments"),
            ("apps", "StatefulSet", "v1", "statefulsets"),
            ("apps", "DaemonSet", "v1", "daemonsets"),
            ("apps", "ReplicaSet", "v1", "replicasets"),
            ("batch", "Job", "v1", "jobs"),
            ("batch", "CronJob", "v1", "cronjobs"),
            ("", "Pod", "v1", "pods"),
            ("gateway.networking.k8s.io", "Gateway", "v1", "gateways"),
        ];
        for (group, kind, version, plural) in entries {
            gk.insert(
                (group.to_string(), kind.to_string()),
                crate::kube::discovery::KindInfo {
                    group: group.to_string(),
                    version: version.to_string(),
                    plural: plural.to_string(),
                    namespaced: true,
                    listable: true,
                },
            );
        }
        gk
    }

    fn test_spec() -> DeleteResourceSpec {
        DeleteResourceSpec {
            group: "".to_string(),
            kind: "ConfigMap".to_string(),
            namespace: Some("ns".to_string()),
            name: "cm1".to_string(),
        }
    }

    fn empty_plan() -> crate::teardown::planner::TeardownPlan {
        crate::teardown::planner::TeardownPlan {
            targets: vec![],
            preflight: crate::teardown::planner::Preflight { checks: vec![] },
            phases: vec![],
            blockers: vec![],
            warnings: vec![],
            snapshot_taken_at: "".into(),
            dependency_edges: vec![],
            operator_inventory: vec![],
            explicit_decisions: vec![],
            explicit_deletes: vec![],
        }
    }

    #[tokio::test]
    async fn resolve_404_one_request_not_found() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                count.fetch_add(1, Ordering::SeqCst);
                send.send_response(status_response(404, "NotFound"));
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let result =
            resolve_explicit_delete_targets(&client, &[test_spec()], &empty_plan(), &test_gk_map())
                .await;

        drop(client);
        spawned.abort();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "404 must not retry"
        );
    }

    #[tokio::test]
    async fn resolve_403_one_request_fails() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((_req, send)) = handle.next_request().await {
                count.fetch_add(1, Ordering::SeqCst);
                send.send_response(status_response(403, "Forbidden"));
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let result =
            resolve_explicit_delete_targets(&client, &[test_spec()], &empty_plan(), &test_gk_map())
                .await;

        drop(client);
        spawned.abort();

        assert!(result.is_err());
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "403 must not retry"
        );
    }

    #[tokio::test]
    async fn resolve_500_then_200_recovers() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = request_count.clone();

        let (mock_service, handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let spawned = tokio::spawn(async move {
            let mut handle = pin!(handle);
            while let Some((req, send)) = handle.next_request().await {
                let n = count.fetch_add(1, Ordering::SeqCst);
                let uri = req.uri().to_string();
                if uri.contains("configmaps") && !uri.contains('?') {
                    if n == 0 {
                        send.send_response(status_response(500, "InternalServerError"));
                    } else {
                        send.send_response(json_response(serde_json::json!({
                            "apiVersion": "v1", "kind": "ConfigMap",
                            "metadata": {"name": "cm1", "namespace": "ns", "uid": "cm-uid-1"}
                        })));
                    }
                } else {
                    // LIST for ref scan — return empty
                    send.send_response(json_response(serde_json::json!({
                        "apiVersion": "v1", "kind": "List",
                        "metadata": {"resourceVersion": "1"}, "items": []
                    })));
                }
            }
        });

        let client = ::kube::Client::new(mock_service, "default");
        let result =
            resolve_explicit_delete_targets(&client, &[test_spec()], &empty_plan(), &test_gk_map())
                .await;

        drop(client);
        spawned.abort();

        assert!(result.is_ok(), "500→200 must recover: {:?}", result.err());
        let targets = result.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].uid, "cm-uid-1");
        assert!(
            request_count.load(Ordering::SeqCst) >= 2,
            "500→200 must use at least 2 requests (GET retry + ref scan LISTs)"
        );
    }
}

#[cfg(test)]
mod config_parse_tests {
    use super::*;

    #[test]
    fn full_teardown_config_parses_as_apply_set_config() {
        let config_str = std::fs::read_to_string("configs/full-teardown.json")
            .expect("configs/full-teardown.json should exist");
        let config: ApplySetConfig = serde_json::from_str(&config_str)
            .expect("configs/full-teardown.json must parse as ApplySetConfig");
        assert!(!config.operators.is_empty(), "config should have operators");
        // Validate every DeleteResourceSpec
        for entry in &config.operators {
            for spec in &entry.delete_resources {
                spec.validate().unwrap_or_else(|e| {
                    panic!(
                        "delete_resources entry {}/{} failed validation: {}",
                        spec.kind, spec.name, e
                    )
                });
            }
        }
    }

    #[test]
    fn config_with_unknown_field_fails() {
        let bad = r#"{"operators":[{"name":"test","delete_resources":[{"group":"","kind":"Svc","name":"x","reason":"extra"}]}]}"#;
        let result = serde_json::from_str::<ApplySetConfig>(bad);
        assert!(result.is_err(), "unknown field 'reason' must be rejected");
    }

    #[test]
    fn config_delete_resource_validate_rejects_empty_kind() {
        let spec = DeleteResourceSpec {
            group: String::new(),
            kind: String::new(),
            namespace: None,
            name: "test".to_string(),
        };
        assert!(
            spec.validate().is_err(),
            "empty kind should fail validation"
        );
    }
}
