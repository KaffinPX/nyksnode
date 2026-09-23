use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Paragraph;

use super::snapshot::Snapshot;

pub fn draw(frame: &mut Frame, area: Rect, snapshot: &Snapshot) {
    let lines = vec![
        Line::from(format!("Height:      {}", snapshot.height)),
        Line::from(format!("Chain tip:   {}", snapshot.tip_height)),
        Line::from(""),
        Line::from(vec![
            Span::raw("Total:       "),
            Span::styled(
                &snapshot.total_balance,
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(" NYKS"),
        ]),
        Line::from(format!("Spendable:   {} NYKS", snapshot.spendable_balance)),
        Line::from(format!("Timelocked:  {} NYKS", snapshot.timelocked_balance)),
        Line::from(format!(
            "Unconfirmed: {} NYKS",
            snapshot.unconfirmed_balance
        )),
        Line::from(format!("Outgoing:    {} NYKS", snapshot.outgoing_balance)),
        Line::from(format!("UTXOs:       {}", snapshot.utxo_count)),
    ];

    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Balance ")),
        area,
    );
}
