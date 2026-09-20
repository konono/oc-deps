use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
};

use crate::kube::resource::ResourceId;
use crate::teardown::app::{AppState, DraftAction};
use crate::teardown::plan::ReviewMetadata;
use crate::teardown::planner::{Action, TeardownPlan};
use crate::teardown::runtime::{ResourceRuntimeState, RuntimeEntry, StateSummary};

/// Draw the Plan Review screen.
pub fn draw_plan_review(
    f: &mut Frame,
    plan: &TeardownPlan,
    app: &AppState,
    review_items: &[(usize, usize, ResourceId, Option<ReviewMetadata>)],
    selected_index: usize,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // title
            Constraint::Min(10),   // plan actions
            Constraint::Length(5), // review items
            Constraint::Length(3),  // help
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new(Line::from(vec![
        Span::styled(" Plan Review ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(format!("— {} phases, ", plan.phases.len())),
        Span::raw(format!("{} REVIEW items", review_items.len())),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Plan summary — show all actions
    let mut summary_items = Vec::new();
    for phase in &plan.phases {
        let mut delete_count = 0;
        let mut expect_count = 0;
        let mut keep_count = 0;
        let mut review_count = 0;
        for action in &phase.actions {
            match action {
                Action::Delete { .. } => delete_count += 1,
                Action::ExpectGone { .. } => expect_count += 1,
                Action::Keep { .. } => keep_count += 1,
                Action::Review { .. } => review_count += 1,
                _ => {}
            }
        }
        let line = format!(
            "  {}: {} DELETE, {} EXPECT, {} KEEP, {} REVIEW",
            phase.name, delete_count, expect_count, keep_count, review_count
        );
        summary_items.push(ListItem::new(Line::from(line)));
    }
    let summary = List::new(summary_items)
        .block(Block::default().borders(Borders::ALL).title(" Phases "));
    f.render_widget(summary, chunks[1]);

    // Review items (navigable)
    let mut review_list_items = Vec::new();
    for (i, (_, _, res, _)) in review_items.iter().enumerate() {
        let override_status = app.draft_overrides.iter().find(|o| {
            o.resource.kind == res.kind
                && o.resource.name == res.name
                && o.resource.namespace == res.namespace
                && o.resource.group == res.group
        });

        let status_marker = match override_status.map(|o| &o.new_action) {
            Some(DraftAction::Delete) => "→ DELETE",
            Some(DraftAction::Keep) => "→ KEEP",
            None => "REVIEW",
        };

        let prefix = if i == selected_index { "▶ " } else { "  " };
        let style = if i == selected_index {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        let ns = res.namespace.as_deref().unwrap_or("cluster");
        let line = format!(
            "{}{} {}/{} ({}) [{}]",
            prefix, status_marker, res.kind, res.name, ns, res.group
        );
        review_list_items.push(ListItem::new(Line::from(line)).style(style));
    }
    let review_list = List::new(review_list_items)
        .block(Block::default().borders(Borders::ALL).title(" REVIEW Items "));
    f.render_widget(review_list, chunks[2]);

    // Help
    let help = Paragraph::new(Line::from(vec![
        Span::styled(" a", Style::default().fg(Color::Green)),
        Span::raw(" approve  "),
        Span::styled("K", Style::default().fg(Color::Green)),
        Span::raw(" keep  "),
        Span::styled("↑↓", Style::default().fg(Color::Green)),
        Span::raw(" navigate  "),
        Span::styled("s/Enter", Style::default().fg(Color::Green)),
        Span::raw(" start execution  "),
        Span::styled("q", Style::default().fg(Color::Green)),
        Span::raw(" quit"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[3]);
}

/// Draw the Execution screen — live resource state from RuntimeStateStore.
pub fn draw_execution(
    f: &mut Frame,
    entries: &[RuntimeEntry],
    summary: &StateSummary,
    current_phase: usize,
    total_phases: usize,
    elapsed_secs: u64,
    paused: bool,
    error_msg: Option<&str>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // title + progress
            Constraint::Length(3),  // gauge
            Constraint::Min(10),   // resource list
            Constraint::Length(3),  // summary
            Constraint::Length(3),  // help
        ])
        .split(f.area());

    // Title
    let status = if paused {
        Span::styled(" PAUSED ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else if let Some(err) = error_msg {
        Span::styled(
            format!(" ERROR: {} ", err),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" Executing ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    };

    let title = Paragraph::new(Line::from(vec![
        status,
        Span::raw(format!("Phase {}/{} ", current_phase, total_phases)),
        Span::styled(format!("({}s)", elapsed_secs), Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Progress gauge — Recreated is a blocker (new UID, needs re-plan), not resolved
    let resolved = summary.gone + summary.keep;
    let blockers = summary.recreated + summary.failed + summary.stalled;
    let ratio = if summary.total > 0 {
        resolved as f64 / summary.total as f64
    } else {
        0.0
    };
    let label = if blockers > 0 {
        format!("{}/{} resolved, {} blocked", resolved, summary.total, blockers)
    } else {
        format!("{}/{} resolved", resolved, summary.total)
    };
    let gauge_color = if blockers > 0 { Color::Yellow } else { Color::Green };
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Progress "))
        .gauge_style(Style::default().fg(gauge_color))
        .ratio(ratio.min(1.0))
        .label(label);
    f.render_widget(gauge, chunks[1]);

    // Resource list — sorted by phase_index, then state priority
    let mut sorted: Vec<&RuntimeEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        a.phase_index.cmp(&b.phase_index)
            .then_with(|| state_priority(&a.state).cmp(&state_priority(&b.state)))
    });

    let visible_height = chunks[2].height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = sorted
        .iter()
        .take(visible_height.max(1))
        .map(|entry| {
            let (icon, color) = state_style(&entry.state);
            let ns = entry.resource.namespace.as_deref().unwrap_or("cluster");
            let line = Line::from(vec![
                Span::styled(
                    format!(" {} ", icon),
                    Style::default().fg(color),
                ),
                Span::styled(
                    format!("{}/{}", entry.resource.kind, entry.resource.name),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!(" ({}) ", ns),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{}", entry.state),
                    Style::default().fg(color),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let overflow = if sorted.len() > visible_height {
        format!(" +{} more ", sorted.len() - visible_height)
    } else {
        String::new()
    };

    let resource_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(format!(" Resources{}", overflow)));
    f.render_widget(resource_list, chunks[2]);

    // Summary bar
    let summary_text = Paragraph::new(Line::from(vec![
        Span::styled(format!(" {} Gone", summary.gone), Style::default().fg(Color::Green)),
        Span::raw("  "),
        Span::styled(format!("{} Deleting", summary.deleting), Style::default().fg(Color::Yellow)),
        Span::raw("  "),
        Span::styled(format!("{} FinBlocked", summary.finalizer_blocked), Style::default().fg(Color::Magenta)),
        Span::raw("  "),
        Span::styled(format!("{} Stalled", summary.stalled), Style::default().fg(Color::Red)),
        Span::raw("  "),
        Span::styled(format!("{} Failed", summary.failed), Style::default().fg(Color::Red)),
        Span::raw("  "),
        Span::styled(format!("{} Keep", summary.keep), Style::default().fg(Color::Cyan)),
        Span::raw("  "),
        Span::styled(format!("{} Recreated", summary.recreated), Style::default().fg(Color::Red)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(summary_text, chunks[3]);

    // Help
    let help = Paragraph::new(Line::from(vec![
        Span::styled(" p", Style::default().fg(Color::Green)),
        Span::raw(" pause  "),
        Span::styled("q/Esc", Style::default().fg(Color::Green)),
        Span::raw(" abort  "),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[4]);
}

/// Per-resource cleanup state for rendering.
#[derive(Clone, Debug, Default)]
pub enum ResidualResourceState {
    #[default]
    Pending,
    Validating,
    DeleteRequested,
    WaitingGone,
    Gone,
    Skipped(String),
    Failed(String),
}

/// Draw the Residual Cleanup screen.
pub fn draw_residual(
    f: &mut Frame,
    residuals: &[(ResourceId, String)],
    selected: &[ResourceId],
    cursor: usize,
    status_msg: Option<&str>,
    cleanup_states: Option<&std::collections::HashMap<ResourceId, ResidualResourceState>>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // title
            Constraint::Min(10),   // residual list
            Constraint::Length(3),  // help
        ])
        .split(f.area());

    // Title
    let title_text = if let Some(msg) = status_msg {
        format!(" Residual Cleanup — {} ", msg)
    } else {
        format!(" Residual Cleanup — {} items ", residuals.len())
    };
    let title = Paragraph::new(Line::from(vec![
        Span::styled(title_text, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Residual items — show cleanup state per resource when available
    let items: Vec<ListItem> = residuals
        .iter()
        .enumerate()
        .map(|(i, (res, reason))| {
            let is_selected = selected.iter().any(|s| {
                s.kind == res.kind && s.name == res.name
                    && s.namespace == res.namespace && s.group == res.group
            });
            let prefix = if i == cursor { "▶ " } else { "  " };

            let cleanup_state = cleanup_states
                .and_then(|states| states.get(res));

            let (state_marker, style) = match cleanup_state {
                Some(ResidualResourceState::Validating) => (
                    "⏳ VALIDATING",
                    Style::default().fg(Color::Yellow),
                ),
                Some(ResidualResourceState::DeleteRequested) => (
                    "◐ DELETE SENT",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Some(ResidualResourceState::WaitingGone) => (
                    "◑ WAITING GONE",
                    Style::default().fg(Color::Yellow),
                ),
                Some(ResidualResourceState::Gone) => (
                    "✓ GONE",
                    Style::default().fg(Color::Green),
                ),
                Some(ResidualResourceState::Skipped(_)) => (
                    "⚠ SKIPPED",
                    Style::default().fg(Color::DarkGray),
                ),
                Some(ResidualResourceState::Failed(_)) => (
                    "✗ FAILED",
                    Style::default().fg(Color::Red),
                ),
                _ => {
                    let check = if is_selected { "[x]" } else { "[ ]" };
                    let s = if i == cursor {
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    } else if is_selected {
                        Style::default().fg(Color::Red)
                    } else {
                        Style::default()
                    };
                    let ns = res.namespace.as_deref().unwrap_or("cluster");
                    let line = format!(
                        "{}{} {}/{} ({}) — {}",
                        prefix, check, res.kind, res.name, ns, reason
                    );
                    return ListItem::new(Line::from(line)).style(s);
                }
            };

            let ns = res.namespace.as_deref().unwrap_or("cluster");
            let line = format!(
                "{}{} {}/{} ({})",
                prefix, state_marker, res.kind, res.name, ns
            );
            ListItem::new(Line::from(line)).style(style)
        })
        .collect();

    let residual_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Residual Resources "));
    f.render_widget(residual_list, chunks[1]);

    // Help
    let help = Paragraph::new(Line::from(vec![
        Span::styled(" space", Style::default().fg(Color::Green)),
        Span::raw(" toggle  "),
        Span::styled("d", Style::default().fg(Color::Green)),
        Span::raw(" delete selected  "),
        Span::styled("↑↓", Style::default().fg(Color::Green)),
        Span::raw(" navigate  "),
        Span::styled("f", Style::default().fg(Color::Green)),
        Span::raw(" finish run  "),
        Span::styled("q", Style::default().fg(Color::Green)),
        Span::raw(" quit"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[2]);
}

fn state_priority(state: &ResourceRuntimeState) -> u8 {
    match state {
        ResourceRuntimeState::Failed { .. } => 0,
        ResourceRuntimeState::Stalled => 1,
        ResourceRuntimeState::Recreated { .. } => 2,
        ResourceRuntimeState::FinalizerBlocked { .. } => 3,
        ResourceRuntimeState::Deleting => 4,
        ResourceRuntimeState::DeleteRequested => 5,
        ResourceRuntimeState::ExpectingGone => 6,
        ResourceRuntimeState::Planned => 7,
        ResourceRuntimeState::Unknown { .. } => 8,
        ResourceRuntimeState::Review => 9,
        ResourceRuntimeState::Keep => 10,
        ResourceRuntimeState::Gone => 11,
    }
}

fn state_style(state: &ResourceRuntimeState) -> (&'static str, Color) {
    match state {
        ResourceRuntimeState::Planned => ("○", Color::DarkGray),
        ResourceRuntimeState::DeleteRequested => ("◐", Color::Yellow),
        ResourceRuntimeState::Deleting => ("◑", Color::Yellow),
        ResourceRuntimeState::Gone => ("✓", Color::Green),
        ResourceRuntimeState::ExpectingGone => ("◌", Color::Yellow),
        ResourceRuntimeState::Recreated { .. } => ("⟲", Color::Red),
        ResourceRuntimeState::Review => ("?", Color::Magenta),
        ResourceRuntimeState::Keep => ("▪", Color::Cyan),
        ResourceRuntimeState::FinalizerBlocked { .. } => ("⊘", Color::Magenta),
        ResourceRuntimeState::Stalled => ("⏳", Color::Red),
        ResourceRuntimeState::Failed { .. } => ("✗", Color::Red),
        ResourceRuntimeState::Unknown { .. } => ("?", Color::DarkGray),
    }
}
