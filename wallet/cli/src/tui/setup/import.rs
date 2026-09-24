use crossterm::event::KeyCode;
use nyks_wallet_core::entropy::wallet_entropy::WalletEntropy;
use ratatui::Frame;
use ratatui::layout::Alignment;
use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;

use super::layout::centered_rect;
use super::layout::footer_rect;
use super::layout::inset;

/// What the import screen wants the caller to do next.
pub enum Outcome {
    Stay,
    Back,
    Confirmed {
        entropy: WalletEntropy,
        phrase: String,
    },
}

/// The "paste an existing mnemonic" screen.
#[derive(Default)]
pub struct ImportPage {
    input: String,
    error: Option<String>,
}

impl ImportPage {
    /// Handles a key press. Unlike the other screens this never bails on
    /// its own, a bad phrase just shows an inline error and stays put.
    pub fn handle_key(&mut self, code: KeyCode) -> Outcome {
        match code {
            KeyCode::Enter => {
                let words: Vec<String> = self.input.split_whitespace().map(str::to_owned).collect();
                match WalletEntropy::from_phrase(&words) {
                    Ok(entropy) => {
                        return Outcome::Confirmed {
                            entropy,
                            phrase: self.input.clone(),
                        };
                    }
                    Err(e) => self.error = Some(format!("invalid mnemonic: {e}")),
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
                self.error = None;
            }
            KeyCode::Char(c) => {
                self.input.push(c);
                self.error = None;
            }
            KeyCode::Esc => return Outcome::Back,
            _ => {}
        }
        Outcome::Stay
    }

    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();
        let inner = centered_rect(area, 70, 30);
        frame.render_widget(
            Block::default()
                .title(" Import an existing wallet ")
                .borders(Borders::ALL),
            inner,
        );

        frame.render_widget(
            Paragraph::new(vec![
                Line::from("Paste your recovery phrase:"),
                Line::from(""),
                Line::from(Span::styled(
                    self.input.as_str(),
                    Style::default().fg(Color::Yellow),
                )),
            ])
            .wrap(Wrap { trim: true }),
            inset(inner, 1),
        );

        let footer = match &self.error {
            Some(err) => {
                Paragraph::new(Span::styled(err.as_str(), Style::default().fg(Color::Red)))
            }
            None => Paragraph::new("Enter = confirm · Esc = back"),
        };
        frame.render_widget(footer.alignment(Alignment::Center), footer_rect(area));
    }
}
