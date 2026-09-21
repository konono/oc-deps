use anyhow::{Result, bail};
use serde::Serialize;

use crate::kube::resource::ResourceId;

// ──────────────────────────────────────────────────────────────
//  Screen / state
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum AppScreen {
    PlanReview,
    Executing,
    ResidualCleanup,
    Paused,
    Finished,
}

// ──────────────────────────────────────────────────────────────
//  Draft overrides (Plan Review)
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
pub struct DraftOverride {
    pub resource: ResourceId,
    pub original_action: String,
    pub new_action: DraftAction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum DraftAction {
    Delete,
    Keep,
}

// ──────────────────────────────────────────────────────────────
//  Commands
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum AppCommand {
    // Plan Review
    ApproveReview { resource: ResourceId },
    KeepReview { resource: ResourceId },
    ToggleFinalizerRecovery,
    StartExecution,

    // Residual Cleanup
    SelectResidual { resource: ResourceId },
    DeselectResidual { resource: ResourceId },
    DeleteSelected,

    // General
    Pause,
    Finish,
}

// ──────────────────────────────────────────────────────────────
//  App state
// ──────────────────────────────────────────────────────────────

pub struct AppState {
    pub screen: AppScreen,
    pub draft_overrides: Vec<DraftOverride>,
    pub selected_residuals: Vec<ResourceId>,
    pub execution_error: Option<String>,
    /// Finalizer recovery approval — toggled in Plan Review, bound to journal at Start.
    pub finalizer_recovery_approved: bool,
}

impl AppState {
    pub fn new(finalizer_recovery_from_cli: bool) -> Self {
        Self {
            screen: AppScreen::PlanReview,
            draft_overrides: Vec::new(),
            selected_residuals: Vec::new(),
            execution_error: None,
            finalizer_recovery_approved: finalizer_recovery_from_cli,
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Validate
// ──────────────────────────────────────────────────────────────

pub fn validate_command(state: &AppState, cmd: &AppCommand) -> Result<()> {
    match cmd {
        AppCommand::ApproveReview { .. }
        | AppCommand::KeepReview { .. }
        | AppCommand::ToggleFinalizerRecovery => {
            if state.screen != AppScreen::PlanReview {
                bail!("Plan modifications only allowed in Plan Review screen");
            }
        }
        AppCommand::StartExecution => {
            if state.screen != AppScreen::PlanReview {
                bail!("Start only allowed from Plan Review screen");
            }
        }
        AppCommand::SelectResidual { .. }
        | AppCommand::DeselectResidual { .. }
        | AppCommand::DeleteSelected => {
            if state.screen != AppScreen::ResidualCleanup {
                bail!("Residual operations only allowed in Residual Cleanup screen");
            }
        }
        AppCommand::Pause => {
            if state.screen != AppScreen::Executing && state.screen != AppScreen::ResidualCleanup {
                bail!("Pause only allowed during Execution or Residual Cleanup");
            }
        }
        AppCommand::Finish => {
            if state.screen != AppScreen::ResidualCleanup {
                bail!("Finish only allowed from Residual Cleanup screen");
            }
        }
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────
//  Apply (pure state transition — no I/O)
// ──────────────────────────────────────────────────────────────

pub fn apply_command(state: &mut AppState, cmd: &AppCommand) -> Result<()> {
    validate_command(state, cmd)?;

    match cmd {
        AppCommand::ApproveReview { resource } => {
            // Remove any existing override for the same resource
            state.draft_overrides.retain(|o| o.resource != *resource);
            state.draft_overrides.push(DraftOverride {
                resource: resource.clone(),
                original_action: "Review".to_string(),
                new_action: DraftAction::Delete,
            });
        }
        AppCommand::KeepReview { resource } => {
            state.draft_overrides.retain(|o| o.resource != *resource);
            state.draft_overrides.push(DraftOverride {
                resource: resource.clone(),
                original_action: "Review".to_string(),
                new_action: DraftAction::Keep,
            });
        }
        AppCommand::ToggleFinalizerRecovery => {
            state.finalizer_recovery_approved = !state.finalizer_recovery_approved;
        }
        AppCommand::StartExecution => {
            state.screen = AppScreen::Executing;
        }
        AppCommand::SelectResidual { resource } => {
            if !state.selected_residuals.contains(resource) {
                state.selected_residuals.push(resource.clone());
            }
        }
        AppCommand::DeselectResidual { resource } => {
            state.selected_residuals.retain(|r| r != resource);
        }
        AppCommand::DeleteSelected => {
            // Intent signal only — actual deletion happens in the executor layer.
        }
        AppCommand::Pause => {
            state.screen = AppScreen::Paused;
        }
        AppCommand::Finish => {
            state.screen = AppScreen::Finished;
        }
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────
//  Snapshot (JSON-serialisable)
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
pub struct AppStateSnapshot {
    pub screen: AppScreen,
    pub draft_override_count: usize,
    pub draft_overrides: Vec<DraftOverrideSnapshot>,
    pub selected_residual_count: usize,
    pub selected_residuals: Vec<String>,
    pub execution_error: Option<String>,
    pub finalizer_recovery_approved: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DraftOverrideSnapshot {
    pub resource: String,
    pub action: DraftAction,
}

impl From<&AppState> for AppStateSnapshot {
    fn from(state: &AppState) -> Self {
        Self {
            screen: state.screen.clone(),
            draft_override_count: state.draft_overrides.len(),
            draft_overrides: state
                .draft_overrides
                .iter()
                .map(|o| DraftOverrideSnapshot {
                    resource: format!("{}/{}", o.resource.kind, o.resource.name),
                    action: o.new_action.clone(),
                })
                .collect(),
            selected_residual_count: state.selected_residuals.len(),
            selected_residuals: state
                .selected_residuals
                .iter()
                .map(|r| format!("{}/{}", r.kind, r.name))
                .collect(),
            execution_error: state.execution_error.clone(),
            finalizer_recovery_approved: state.finalizer_recovery_approved,
        }
    }
}

// ──────────────────────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn res(name: &str) -> ResourceId {
        ResourceId {
            group: "test.io".to_string(),
            version: "v1".to_string(),
            kind: "Thing".to_string(),
            namespace: Some("ns".to_string()),
            name: name.to_string(),
            uid: Some(format!("uid-{}", name)),
        }
    }

    // ── Plan Review ──

    #[test]
    fn test_approve_review_in_plan_review() {
        let mut s = AppState::new(false);
        assert!(apply_command(&mut s, &AppCommand::ApproveReview { resource: res("a") }).is_ok());
        assert_eq!(s.draft_overrides.len(), 1);
        assert_eq!(s.draft_overrides[0].new_action, DraftAction::Delete);
    }

    #[test]
    fn test_keep_review_in_plan_review() {
        let mut s = AppState::new(false);
        assert!(apply_command(&mut s, &AppCommand::KeepReview { resource: res("b") }).is_ok());
        assert_eq!(s.draft_overrides.len(), 1);
        assert_eq!(s.draft_overrides[0].new_action, DraftAction::Keep);
    }

    #[test]
    fn test_override_replaces_previous() {
        let mut s = AppState::new(false);
        apply_command(&mut s, &AppCommand::ApproveReview { resource: res("a") }).unwrap();
        apply_command(&mut s, &AppCommand::KeepReview { resource: res("a") }).unwrap();
        assert_eq!(s.draft_overrides.len(), 1);
        assert_eq!(s.draft_overrides[0].new_action, DraftAction::Keep);
    }

    #[test]
    fn test_start_transitions_to_executing() {
        let mut s = AppState::new(false);
        apply_command(&mut s, &AppCommand::StartExecution).unwrap();
        assert_eq!(s.screen, AppScreen::Executing);
    }

    // ── Execution rejects plan changes ──

    #[test]
    fn test_execution_rejects_approve() {
        let mut s = AppState::new(false);
        s.screen = AppScreen::Executing;
        assert!(apply_command(&mut s, &AppCommand::ApproveReview { resource: res("a") }).is_err());
    }

    #[test]
    fn test_execution_rejects_keep() {
        let mut s = AppState::new(false);
        s.screen = AppScreen::Executing;
        assert!(apply_command(&mut s, &AppCommand::KeepReview { resource: res("a") }).is_err());
    }

    #[test]
    fn test_execution_rejects_start() {
        let mut s = AppState::new(false);
        s.screen = AppScreen::Executing;
        assert!(apply_command(&mut s, &AppCommand::StartExecution).is_err());
    }

    // ── Residual Cleanup ──

    #[test]
    fn test_residual_select_requires_cleanup_screen() {
        let mut s = AppState::new(false); // PlanReview
        assert!(apply_command(&mut s, &AppCommand::SelectResidual { resource: res("x") }).is_err());
    }

    #[test]
    fn test_residual_select_deselect() {
        let mut s = AppState::new(false);
        s.screen = AppScreen::ResidualCleanup;
        apply_command(&mut s, &AppCommand::SelectResidual { resource: res("a") }).unwrap();
        assert_eq!(s.selected_residuals.len(), 1);
        apply_command(&mut s, &AppCommand::DeselectResidual { resource: res("a") }).unwrap();
        assert_eq!(s.selected_residuals.len(), 0);
    }

    #[test]
    fn test_residual_select_idempotent() {
        let mut s = AppState::new(false);
        s.screen = AppScreen::ResidualCleanup;
        apply_command(&mut s, &AppCommand::SelectResidual { resource: res("a") }).unwrap();
        apply_command(&mut s, &AppCommand::SelectResidual { resource: res("a") }).unwrap();
        assert_eq!(s.selected_residuals.len(), 1);
    }

    #[test]
    fn test_delete_selected_requires_cleanup_screen() {
        let mut s = AppState::new(false);
        s.screen = AppScreen::Executing;
        assert!(apply_command(&mut s, &AppCommand::DeleteSelected).is_err());
    }

    // ── Pause ──

    #[test]
    fn test_pause_from_executing() {
        let mut s = AppState::new(false);
        s.screen = AppScreen::Executing;
        apply_command(&mut s, &AppCommand::Pause).unwrap();
        assert_eq!(s.screen, AppScreen::Paused);
    }

    #[test]
    fn test_pause_from_residual_cleanup() {
        let mut s = AppState::new(false);
        s.screen = AppScreen::ResidualCleanup;
        apply_command(&mut s, &AppCommand::Pause).unwrap();
        assert_eq!(s.screen, AppScreen::Paused);
    }

    #[test]
    fn test_pause_from_plan_review_rejected() {
        let mut s = AppState::new(false);
        assert!(apply_command(&mut s, &AppCommand::Pause).is_err());
    }

    // ── Finish ──

    #[test]
    fn test_finish_only_from_residual_cleanup() {
        let mut s = AppState::new(false);
        s.screen = AppScreen::ResidualCleanup;
        apply_command(&mut s, &AppCommand::Finish).unwrap();
        assert_eq!(s.screen, AppScreen::Finished);
    }

    #[test]
    fn test_finish_rejected_from_other_screens() {
        for screen in [
            AppScreen::PlanReview,
            AppScreen::Executing,
            AppScreen::Paused,
        ] {
            let mut s = AppState::new(false);
            s.screen = screen.clone();
            assert!(
                apply_command(&mut s, &AppCommand::Finish).is_err(),
                "Finish must be rejected from {:?}",
                screen
            );
        }
    }

    // ── Snapshot ──

    #[test]
    fn test_snapshot_reflects_state() {
        let mut s = AppState::new(false);
        apply_command(&mut s, &AppCommand::ApproveReview { resource: res("x") }).unwrap();
        let snap = AppStateSnapshot::from(&s);
        assert_eq!(snap.screen, AppScreen::PlanReview);
        assert_eq!(snap.draft_override_count, 1);
        assert_eq!(snap.draft_overrides[0].resource, "Thing/x");
        assert!(!snap.finalizer_recovery_approved);
    }

    #[test]
    fn snapshot_reflects_toggle_finalizer_recovery() {
        let mut s = AppState::new(false);
        assert!(!AppStateSnapshot::from(&s).finalizer_recovery_approved);
        apply_command(&mut s, &AppCommand::ToggleFinalizerRecovery).unwrap();
        assert!(AppStateSnapshot::from(&s).finalizer_recovery_approved);
        apply_command(&mut s, &AppCommand::ToggleFinalizerRecovery).unwrap();
        assert!(!AppStateSnapshot::from(&s).finalizer_recovery_approved);
    }

    #[test]
    fn toggle_finalizer_recovery_in_plan_review() {
        let mut s = AppState::new(false);
        assert!(!s.finalizer_recovery_approved);
        apply_command(&mut s, &AppCommand::ToggleFinalizerRecovery).unwrap();
        assert!(s.finalizer_recovery_approved);
        apply_command(&mut s, &AppCommand::ToggleFinalizerRecovery).unwrap();
        assert!(!s.finalizer_recovery_approved);
    }

    #[test]
    fn toggle_finalizer_recovery_blocked_after_start() {
        let mut s = AppState::new(false);
        apply_command(&mut s, &AppCommand::StartExecution).unwrap();
        let err = apply_command(&mut s, &AppCommand::ToggleFinalizerRecovery);
        assert!(err.is_err(), "Toggle must be rejected after StartExecution");
    }

    #[test]
    fn cli_flag_seeds_finalizer_recovery() {
        let s = AppState::new(true);
        assert!(s.finalizer_recovery_approved);
    }

    // ── Headless command JSON roundtrip ──

    #[test]
    fn headless_command_json_roundtrip() {
        let commands = vec![
            (
                r#"{"ApproveReview":{"resource":{"group":"test.io","version":"v1","kind":"Thing","namespace":"ns","name":"a","uid":"uid-a"}}}"#,
                "ApproveReview",
            ),
            (
                r#"{"KeepReview":{"resource":{"group":"test.io","version":"v1","kind":"Thing","namespace":"ns","name":"b","uid":"uid-b"}}}"#,
                "KeepReview",
            ),
            (r#""ToggleFinalizerRecovery""#, "ToggleFinalizerRecovery"),
            (r#""StartExecution""#, "StartExecution"),
            (r#""Pause""#, "Pause"),
            (r#""Finish""#, "Finish"),
        ];
        for (json, label) in &commands {
            let cmd: AppCommand = serde_json::from_str(json)
                .unwrap_or_else(|e| panic!("Failed to parse {}: {}", label, e));
            let re_json = serde_json::to_string(&cmd).unwrap();
            let cmd2: AppCommand = serde_json::from_str(&re_json).unwrap();
            assert_eq!(
                format!("{:?}", cmd),
                format!("{:?}", cmd2),
                "roundtrip failed for {}",
                label
            );
        }
    }

    #[test]
    fn headless_toggle_then_start_fixes_flag() {
        let mut s = AppState::new(false);
        let toggle: AppCommand = serde_json::from_str(r#""ToggleFinalizerRecovery""#).unwrap();
        apply_command(&mut s, &toggle).unwrap();
        assert!(s.finalizer_recovery_approved);

        let start: AppCommand = serde_json::from_str(r#""StartExecution""#).unwrap();
        apply_command(&mut s, &start).unwrap();
        assert_eq!(s.screen, AppScreen::Executing);
        assert!(s.finalizer_recovery_approved, "flag must be fixed at Start");

        // After Start, toggle must be rejected
        assert!(apply_command(&mut s, &toggle).is_err());
    }

    /// Simulates the headless script sequence: parse JSON commands, apply them,
    /// then verify the value that would be passed to `create_run_journal`.
    /// This mirrors the actual code path in main.rs headless script mode.
    #[test]
    fn headless_script_sequence_journal_receives_app_flag() {
        let script_lines = [r#""ToggleFinalizerRecovery""#, r#""StartExecution""#];

        let mut app = AppState::new(false);
        for line in &script_lines {
            let cmd: AppCommand = serde_json::from_str(line).unwrap();
            let _ = apply_command(&mut app, &cmd);
        }

        // This is the value main.rs passes to create_run_journal:
        //   `app.finalizer_recovery_approved`
        assert!(
            app.finalizer_recovery_approved,
            "journal must receive true after toggle in script"
        );
        assert_eq!(app.screen, AppScreen::Executing);

        // Double-toggle → false: verify the journal would get false
        let mut app2 = AppState::new(false);
        let cmds = [
            r#""ToggleFinalizerRecovery""#,
            r#""ToggleFinalizerRecovery""#,
            r#""StartExecution""#,
        ];
        for line in &cmds {
            let cmd: AppCommand = serde_json::from_str(line).unwrap();
            let _ = apply_command(&mut app2, &cmd);
        }
        assert!(
            !app2.finalizer_recovery_approved,
            "double-toggle must result in false for journal"
        );
    }

    /// CLI flag=true without toggle: journal receives true directly.
    #[test]
    fn headless_cli_flag_true_no_toggle_journal_receives_true() {
        let mut app = AppState::new(true);
        let start: AppCommand = serde_json::from_str(r#""StartExecution""#).unwrap();
        apply_command(&mut app, &start).unwrap();
        assert!(
            app.finalizer_recovery_approved,
            "CLI flag=true must propagate to journal without toggle"
        );
    }

    #[test]
    fn headless_invalid_command_rejected() {
        let result: Result<AppCommand, _> = serde_json::from_str(r#""NotACommand""#);
        assert!(result.is_err());
    }
}
