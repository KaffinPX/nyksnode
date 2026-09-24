use anyhow::Result;
use crossterm::event::KeyCode;
use nyks_wallet_core::entropy::secret_key_material::SecretKeyMaterial;
use nyks_wallet_core::entropy::wallet_entropy::WalletEntropy;
use ratatui::Frame;
use ratatui::layout::Alignment;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;

use super::layout::centered_rect;
use super::layout::footer_rect;
use super::layout::inset;

/// What the create screen wants the caller to do next.
pub enum Outcome {
    Stay,
    Back,
    Confirmed {
        entropy: WalletEntropy,
        phrase: String,
    },
}

/// The "write down your new mnemonic" screen.
pub struct CreatePage {
    words: Vec<String>,
}

impl CreatePage {
    /// Generates a fresh mnemonic and starts the screen on it.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            words: generate_words(),
        })
    }

    pub fn handle_key(&mut self, code: KeyCode) -> Result<Outcome> {
        match code {
            KeyCode::Enter => {
                let phrase = self.words.join(" ");
                let entropy = WalletEntropy::from_phrase(self.words.as_slice()).map_err(|e| {
                    anyhow::anyhow!("failed to derive keys from generated mnemonic: {e}")
                })?;
                return Ok(Outcome::Confirmed { entropy, phrase });
            }
            KeyCode::Char('r') => self.words = generate_words(),
            KeyCode::Esc => return Ok(Outcome::Back),
            _ => {}
        }
        Ok(Outcome::Stay)
    }

    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();
        let inner = centered_rect(area, 70, 60);
        frame.render_widget(
            Block::default()
                .title(" Write down your recovery phrase ")
                .borders(Borders::ALL),
            inner,
        );

        let numbered: Vec<Line> = self
            .words
            .chunks(4)
            .enumerate()
            .map(|(row, chunk)| {
                Line::from(
                    chunk
                        .iter()
                        .enumerate()
                        .map(|(i, w)| Span::raw(format!("{:>2}. {:<10}", row * 4 + i + 1, w)))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        frame.render_widget(
            Paragraph::new(numbered).wrap(Wrap { trim: true }),
            inset(inner, 1),
        );
        frame.render_widget(
            Paragraph::new("Enter = I've saved it, continue · r = regenerate · Esc = back")
                .alignment(Alignment::Center),
            footer_rect(area),
        );
    }
}

fn generate_words() -> Vec<String> {
    let secret = SecretKeyMaterial::random();
    secret.to_phrase()
}
