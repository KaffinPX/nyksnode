use std::time::Duration;
use std::time::Instant;

use arboard::Clipboard;
use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::Constraint;
use ratatui::layout::Direction;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
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
use ratatui::widgets::Wrap;

use super::snapshot::Snapshot;

/// How long a "Copied!" / error message stays visible after pressing `c`.
const FEEDBACK_DURATION: Duration = Duration::from_secs(2);

/// Which of the wallet's two address types is currently shown.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum AddressKind {
    #[default]
    Generation,
    Symmetric,
}

impl AddressKind {
    const ALL: [AddressKind; 2] = [AddressKind::Generation, AddressKind::Symmetric];

    fn label(self) -> &'static str {
        match self {
            AddressKind::Generation => "Generation",
            AddressKind::Symmetric => "Symmetric",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|k| *k == self).unwrap()
    }

    fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    fn prev(self) -> Self {
        let len = Self::ALL.len();
        Self::ALL[(self.index() + len - 1) % len]
    }

    fn address(self, snapshot: &Snapshot) -> &str {
        match self {
            AddressKind::Generation => &snapshot.generation_address,
            AddressKind::Symmetric => &snapshot.symmetric_address,
        }
    }

    /// Trade-offs of this address type.
    fn explanation(self) -> &'static str {
        match self {
            AddressKind::Generation => {
                "Fully private, but longer than symmetric addresses, making them less convenient to share."
            }
            AddressKind::Symmetric => {
                "Short and easy to share, but anyone you give it to can see and link the UTXOs sent to it."
            }
        }
    }
}

/// Transient status shown after a copy attempt.
struct CopyFeedback {
    message: String,
    ok: bool,
    at: Instant,
}

/// State for the Address tab: which address type is selected, plus the
/// most recent copy-to-clipboard result (if any).
#[derive(Default)]
pub struct AddressPage {
    selected: AddressKind,
    feedback: Option<CopyFeedback>,
}

impl AddressPage {
    /// Handles a key press while the Address tab is active.
    pub fn handle_key(&mut self, code: KeyCode, snapshot: &Snapshot) {
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.prev(),
            KeyCode::Down | KeyCode::Char('j') => self.selected = self.selected.next(),
            KeyCode::Char('c') => self.copy_to_clipboard(snapshot),
            _ => {}
        }
    }

    fn copy_to_clipboard(&mut self, snapshot: &Snapshot) {
        let address = self.selected.address(snapshot).to_owned();
        let (ok, message) = match Clipboard::new().and_then(|mut cb| cb.set_text(address)) {
            Ok(()) => (
                true,
                format!("Copied {} address to clipboard.", self.selected.label()),
            ),
            Err(e) => (false, format!("Couldn't copy to clipboard: {e}")),
        };
        self.feedback = Some(CopyFeedback {
            message,
            ok,
            at: Instant::now(),
        });
    }

    /// Draws a small two-item selector (Generation / Symmetric) with the
    /// chosen address and a plain-language explanation of its trade-offs
    /// below.
    pub fn draw(&self, frame: &mut Frame, area: Rect, snapshot: &Snapshot) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Min(0)])
            .split(area);

        let items: Vec<ListItem> = AddressKind::ALL
            .iter()
            .map(|kind| {
                let style = if *kind == self.selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Magenta)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(
                    format!(" {} ", kind.label()),
                    style,
                )))
            })
            .collect();

        frame.render_widget(
            List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Address type (↑/↓) "),
            ),
            layout[0],
        );

        let mut lines = vec![
            Line::from(Span::styled(
                self.selected.address(snapshot),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(self.selected.explanation()),
            Line::from(""),
        ];
        lines.push(self.feedback_line());

        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" {} address ", self.selected.label())),
                )
                .wrap(Wrap { trim: true }),
            layout[1],
        );
    }

    /// The line shown at the bottom of the address panel: a recent copy
    /// result while it's still fresh, otherwise the standing "press c" hint.
    fn feedback_line(&self) -> Line<'static> {
        match &self.feedback {
            Some(feedback) if feedback.at.elapsed() < FEEDBACK_DURATION => {
                let color = if feedback.ok {
                    Color::Green
                } else {
                    Color::Red
                };
                Line::from(Span::styled(
                    feedback.message.clone(),
                    Style::default().fg(color),
                ))
            }
            _ => Line::from(Span::styled(
                "c = copy address to clipboard",
                Style::default().fg(Color::DarkGray),
            )),
        }
    }
}
