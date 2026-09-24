use crossterm::event::KeyCode;
use nyks_consensus::network::Network;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::address::Recipient;
use nyks_wallet_sdk::wallet::Wallet;
use ratatui::Frame;
use ratatui::layout::Constraint;
use ratatui::layout::Direction;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;
use tokio::sync::oneshot;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Recipient,
    Amount,
    Fee,
}

impl Field {
    const ALL: [Field; 3] = [Field::Recipient, Field::Amount, Field::Fee];

    fn label(self) -> &'static str {
        match self {
            Field::Recipient => "Recipient",
            Field::Amount => "Amount",
            Field::Fee => "Fee",
        }
    }

    fn placeholder(self) -> &'static str {
        match self {
            Field::Recipient => "nolgam1... (recipient's address)",
            Field::Amount => "e.g. 1.5",
            Field::Fee => "e.g. 0.01",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|f| *f == self).unwrap()
    }

    fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    fn prev(self) -> Self {
        let len = Self::ALL.len();
        Self::ALL[(self.index() + len - 1) % len]
    }
}

#[derive(Default)]
struct FormInputs {
    recipient: String,
    amount: String,
    fee: String,
}

fn field_mut(inputs: &mut FormInputs, field: Field) -> &mut String {
    match field {
        Field::Recipient => &mut inputs.recipient,
        Field::Amount => &mut inputs.amount,
        Field::Fee => &mut inputs.fee,
    }
}

fn field_value(inputs: &FormInputs, field: Field) -> &str {
    match field {
        Field::Recipient => &inputs.recipient,
        Field::Amount => &inputs.amount,
        Field::Fee => &inputs.fee,
    }
}

fn parse_form(inputs: &FormInputs, network: Network) -> Result<Step, String> {
    let recipient_str = inputs.recipient.trim();
    if recipient_str.is_empty() {
        return Err("Missing address (e.g. nolgam...)".to_owned());
    }
    let recipient = Address::from_bech32m(recipient_str, network)
        .map_err(|e| format!("Invalid recipient: {e}. Is it on the wrong network?"))?;

    let amount_str = inputs.amount.trim();
    let amount = NativeCurrencyAmount::coins_from_str(amount_str)
        .map_err(|_| format!("Invalid amount '{amount_str}'. Try using a number (e.g. 1.5)."))?;

    let fee_str = inputs.fee.trim();
    let fee = NativeCurrencyAmount::coins_from_str(fee_str)
        .map_err(|_| format!("Invalid fee '{fee_str}'. Try using a number (e.g. 0.001)."))?;

    Ok(Step::Confirm {
        recipient,
        recipient_display: recipient_str.to_owned(),
        amount,
        fee,
    })
}

enum Step {
    Form {
        field: Field,
        error: Option<String>,
    },
    Confirm {
        recipient: Address,
        recipient_display: String,
        amount: NativeCurrencyAmount,
        fee: NativeCurrencyAmount,
    },
    Proving,
    Result {
        ok: bool,
        message: String,
    },
}

impl Default for Step {
    fn default() -> Self {
        Step::Form {
            field: Field::Recipient,
            error: None,
        }
    }
}

#[derive(Default)]
pub struct SendPage {
    inputs: FormInputs,
    step: Step,
    result_rx: Option<oneshot::Receiver<(bool, String)>>,
}

impl SendPage {
    pub fn is_active(&self) -> bool {
        self.result_rx.is_some()
    }

    pub async fn handle_key(&mut self, code: KeyCode, wallet: &Wallet) {
        let step = std::mem::take(&mut self.step);

        self.step = match step {
            Step::Form { field, error } => match code {
                KeyCode::Char(c) => {
                    field_mut(&mut self.inputs, field).push(c);
                    Step::Form { field, error: None }
                }
                KeyCode::Backspace => {
                    field_mut(&mut self.inputs, field).pop();
                    Step::Form { field, error: None }
                }
                KeyCode::Down | KeyCode::Tab => Step::Form {
                    field: field.next(),
                    error,
                },
                KeyCode::Up | KeyCode::BackTab => Step::Form {
                    field: field.prev(),
                    error,
                },
                KeyCode::Enter if field != Field::Fee => Step::Form {
                    field: field.next(),
                    error,
                },
                KeyCode::Enter => match parse_form(&self.inputs, wallet.network) {
                    Ok(confirm) => confirm,
                    Err(message) => Step::Form {
                        field,
                        error: Some(message),
                    },
                },
                KeyCode::Esc => {
                    self.inputs = FormInputs::default();
                    Step::default()
                }
                _ => Step::Form { field, error },
            },
            Step::Confirm {
                recipient,
                recipient_display,
                amount,
                fee,
            } => match code {
                KeyCode::Enter => {
                    let amount_display = amount.to_string();
                    let fee_display = fee.to_string();
                    let (result_tx, result_rx) = oneshot::channel();
                    let wallet = wallet.clone();

                    tokio::spawn(async move {
                        let outcome = match wallet.send(recipient, amount, fee, None).await {
                            Ok(id) => (
                                true,
                                format!(
                                    "Sent {amount_display} NYKS (+ {fee_display} fee) to \
                                     {recipient_display}. Transaction {id} announced."
                                ),
                            ),
                            Err(e) => (false, format!("Failed to submit transaction: {e}.")),
                        };
                        let _ = result_tx.send(outcome);
                    });

                    self.result_rx = Some(result_rx);
                    Step::Proving
                }
                KeyCode::Esc => Step::Form {
                    field: Field::Fee,
                    error: None,
                },
                _ => Step::Confirm {
                    recipient,
                    recipient_display,
                    amount,
                    fee,
                },
            },
            // Ignore all input while proving.
            Step::Proving => Step::Proving,
            Step::Result { .. } => Step::Form {
                field: Field::Recipient,
                error: None,
            },
        };
    }

    /// Only call while `is_active()`.
    pub async fn await_result(&mut self) {
        let Some(rx) = self.result_rx.as_mut() else {
            return;
        };
        let outcome = rx.await;
        self.result_rx = None;

        let (ok, message) =
            outcome.unwrap_or_else(|_| (false, "Send task ended unexpectedly.".to_owned()));

        if ok {
            self.inputs = FormInputs::default();
        }
        self.step = Step::Result { ok, message };
    }

    pub fn draw(&self, frame: &mut Frame, area: Rect) {
        match &self.step {
            Step::Form { field, error } => {
                draw_form(frame, area, &self.inputs, *field, error.as_deref())
            }
            Step::Confirm {
                recipient_display,
                amount,
                fee,
                ..
            } => draw_confirm(frame, area, recipient_display, amount, fee),
            Step::Proving => draw_proving(frame, area),
            Step::Result { ok, message } => draw_result(frame, area, *ok, message),
        }
    }
}

fn draw_form(
    frame: &mut Frame,
    area: Rect,
    inputs: &FormInputs,
    active: Field,
    error: Option<&str>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    for (i, field) in Field::ALL.iter().enumerate() {
        let value = field_value(inputs, *field);
        let is_active = *field == active;

        let (text, style) = if is_active {
            (format!("{value}\u{2588}"), Style::default())
        } else if value.is_empty() {
            (
                field.placeholder().to_owned(),
                Style::default().fg(Color::DarkGray),
            )
        } else {
            (value.to_owned(), Style::default())
        };

        let border_style = if is_active {
            Style::default().fg(Color::Magenta)
        } else {
            Style::default()
        };

        frame.render_widget(
            Paragraph::new(Span::styled(text, style)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style)
                    .title(format!(" {} ", field.label())),
            ),
            chunks[i],
        );
    }

    let footer = match error {
        Some(err) => Line::from(Span::styled(err, Style::default().fg(Color::Red))),
        None => Line::from("Type to edit · Tab/↓ next field · Enter next/confirm · Esc clear"),
    };
    frame.render_widget(Paragraph::new(footer).wrap(Wrap { trim: true }), chunks[3]);
}

fn draw_confirm(
    frame: &mut Frame,
    area: Rect,
    recipient_display: &str,
    amount: &NativeCurrencyAmount,
    fee: &NativeCurrencyAmount,
) {
    let lines = vec![
        Line::from("Confirm this transaction:"),
        Line::from(""),
        Line::from(vec![
            Span::raw("To:     "),
            Span::styled(recipient_display, Style::default().fg(Color::Magenta)),
        ]),
        Line::from(format!("Amount: {amount} NYKS")),
        Line::from(format!("Fee:    {fee} NYKS")),
        Line::from(""),
        Line::from(Span::styled(
            "Enter = send it · Esc = back and edit",
            Style::default().fg(Color::Yellow),
        )),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Confirm send "),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_proving(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "Proving transaction...",
            Style::default().fg(Color::Magenta),
        )),
        Line::from(""),
        Line::from("This can take a while. Please wait."),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Sending... "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_result(frame: &mut Frame, area: Rect, ok: bool, message: &str) {
    let color = if ok { Color::Green } else { Color::Red };
    let title = if ok { " Sent " } else { " Send failed " };

    let lines = vec![
        Line::from(Span::styled(message, Style::default().fg(color))),
        Line::from(""),
        Line::from("Press any key to start another transaction."),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: true }),
        area,
    );
}
