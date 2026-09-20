use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::kube::resource::ResourceId;
use crate::teardown::app::{AppState, DraftAction};
use crate::teardown::plan::ReviewMetadata;
use crate::teardown::planner::{Action, TeardownPlan};

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
