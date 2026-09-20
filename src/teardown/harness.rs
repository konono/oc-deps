//! Headless CLI harness.
//!
//! Drives the same [`AppState`] / [`AppCommand`] reducer used by the
//! TUI, producing deterministic JSON event traces that can be asserted
//! in tests without a terminal.

use serde::Serialize;

use crate::teardown::app::{AppCommand, AppState, AppStateSnapshot, apply_command};

// ──────────────────────────────────────────────────────────────
//  Event trace
// ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct HarnessEvent {
    pub step: usize,
    pub command: String,
    pub result: HarnessResult,
    pub state: AppStateSnapshot,
}

#[derive(Debug, Serialize)]
pub enum HarnessResult {
    Ok,
    Error(String),
}

// ──────────────────────────────────────────────────────────────
//  Scenario runner
// ──────────────────────────────────────────────────────────────

/// Run a sequence of [`AppCommand`]s against an [`AppState`],
/// returning the full event trace.  No Kubernetes I/O is performed
/// — this exercises the pure state-machine layer only.
pub fn run_scenario(initial: AppState, commands: &[AppCommand]) -> Vec<HarnessEvent> {
    let mut state = initial;
    let mut events = Vec::with_capacity(commands.len());

    for (i, cmd) in commands.iter().enumerate() {
        let cmd_str = format!("{:?}", cmd);
        let result = apply_command(&mut state, cmd);

        events.push(HarnessEvent {
            step: i,
            command: cmd_str,
            result: match &result {
                Ok(()) => HarnessResult::Ok,
                Err(e) => HarnessResult::Error(format!("{:#}", e)),
            },
            state: AppStateSnapshot::from(&state),
        });
    }

    events
}

// ──────────────────────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kube::resource::ResourceId;
    use crate::teardown::app::AppScreen;

    fn res(name: &str) -> ResourceId {
        ResourceId {
            group: "test.io".to_string(),
            version: "v1".to_string(),
            kind: "Widget".to_string(),
            namespace: Some("ns".to_string()),
            name: name.to_string(),
            uid: Some(format!("uid-{}", name)),
        }
    }

    #[test]
    fn test_plan_review_to_execution_scenario() {
        let events = run_scenario(
            AppState::new(),
            &[
                AppCommand::ApproveReview { resource: res("a") },
                AppCommand::KeepReview { resource: res("b") },
                AppCommand::StartExecution,
            ],
        );

        assert_eq!(events.len(), 3);

        // Step 0: approve
        assert!(matches!(events[0].result, HarnessResult::Ok));
        assert_eq!(events[0].state.screen, AppScreen::PlanReview);
        assert_eq!(events[0].state.draft_override_count, 1);

        // Step 1: keep
        assert!(matches!(events[1].result, HarnessResult::Ok));
        assert_eq!(events[1].state.draft_override_count, 2);

        // Step 2: start
        assert!(matches!(events[2].result, HarnessResult::Ok));
        assert_eq!(events[2].state.screen, AppScreen::Executing);
    }

    #[test]
    fn test_execution_rejects_plan_changes() {
        let events = run_scenario(
            AppState::new(),
            &[
                AppCommand::StartExecution,
                AppCommand::ApproveReview { resource: res("a") },
            ],
        );

        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].result, HarnessResult::Ok));
        assert!(matches!(events[1].result, HarnessResult::Error(_)));

        // Screen didn't change back
        assert_eq!(events[1].state.screen, AppScreen::Executing);
    }

    #[test]
    fn test_pause_and_finish_scenario() {
        let events = run_scenario(
            AppState::new(),
            &[
                AppCommand::StartExecution,
                AppCommand::Pause,
                AppCommand::Finish,
            ],
        );

        assert_eq!(events.len(), 3);
        assert_eq!(events[1].state.screen, AppScreen::Paused);
        assert_eq!(events[2].state.screen, AppScreen::Finished);
    }

    #[test]
    fn test_residual_cleanup_scenario() {
        let mut state = AppState::new();
        state.screen = AppScreen::ResidualCleanup;

        let events = run_scenario(
            state,
            &[
                AppCommand::SelectResidual { resource: res("r1") },
                AppCommand::SelectResidual { resource: res("r2") },
                AppCommand::DeselectResidual { resource: res("r1") },
                AppCommand::DeleteSelected,
            ],
        );

        assert_eq!(events.len(), 4);
        assert_eq!(events[1].state.selected_residual_count, 2);
        assert_eq!(events[2].state.selected_residual_count, 1);
        assert!(matches!(events[3].result, HarnessResult::Ok));
    }

    #[test]
    fn test_residual_ops_rejected_outside_cleanup_screen() {
        let events = run_scenario(
            AppState::new(), // PlanReview
            &[
                AppCommand::SelectResidual { resource: res("x") },
                AppCommand::DeleteSelected,
            ],
        );

        assert!(matches!(events[0].result, HarnessResult::Error(_)));
        assert!(matches!(events[1].result, HarnessResult::Error(_)));
    }

    #[test]
    fn test_snapshot_json_serializable() {
        let events = run_scenario(
            AppState::new(),
            &[AppCommand::ApproveReview { resource: res("a") }],
        );

        // Must not panic
        let json = serde_json::to_string_pretty(&events).unwrap();
        assert!(json.contains("PlanReview"));
        assert!(json.contains("Widget/a"));
    }

    #[test]
    fn test_full_lifecycle_scenario() {
        // PlanReview → approve → start → pause → finish
        let events = run_scenario(
            AppState::new(),
            &[
                AppCommand::ApproveReview { resource: res("cr1") },
                AppCommand::StartExecution,
                AppCommand::Pause,
                AppCommand::Finish,
            ],
        );

        assert_eq!(events.len(), 4);
        assert_eq!(events[0].state.screen, AppScreen::PlanReview);
        assert_eq!(events[1].state.screen, AppScreen::Executing);
        assert_eq!(events[2].state.screen, AppScreen::Paused);
        assert_eq!(events[3].state.screen, AppScreen::Finished);

        // All succeeded
        assert!(events.iter().all(|e| matches!(e.result, HarnessResult::Ok)));
    }
}
