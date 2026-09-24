use anyhow::Result;
use anyhow::bail;
use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::Alignment;
use ratatui::layout::Constraint;
use ratatui::layout::Direction;
use ratatui::layout::Layout;
use ratatui::style::Color;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::List;
use ratatui::widgets::ListItem;
use ratatui::widgets::Paragraph;

use super::layout::centered_rect;
use super::layout::footer_rect;

const ITEMS: [&str; 2] = ["Create a new wallet", "Import an existing wallet"];

/// What the menu screen wants the caller to do next.
pub enum Outcome {
    Stay,
    GoToCreate,
    GoToImport,
}

/// The entry screen: pick "create" or "import".
#[derive(Default)]
pub struct MenuPage {
    selected: usize,
}

impl MenuPage {
    pub fn handle_key(&mut self, code: KeyCode) -> Result<Outcome> {
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1).min(ITEMS.len() - 1);
            }
            KeyCode::Enter if self.selected == 0 => return Ok(Outcome::GoToCreate),
            KeyCode::Enter => return Ok(Outcome::GoToImport),
            KeyCode::Esc | KeyCode::Char('q') => bail!("setup cancelled"),
            _ => {}
        }
        Ok(Outcome::Stay)
    }

    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();

        let list_items: Vec<ListItem> = ITEMS
            .iter()
            .enumerate()
            .map(|(i, label)| {
                let style = if i == self.selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Magenta)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(format!(" {label} "), style)))
            })
            .collect();

        let popup = centered_rect(area, 50, 30);
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(ITEMS.len() as u16 + 2),
                Constraint::Min(0),
            ])
            .split(popup);

        let block = Block::default()
            .title(" nyks-wallet — no wallet found ")
            .borders(Borders::ALL);
        frame.render_widget(List::new(list_items).block(block), layout[0]);

        frame.render_widget(
            Paragraph::new("↑/↓ or j/k to move · Enter to select · q to quit")
                .alignment(Alignment::Center),
            footer_rect(area),
        );
    }
}
