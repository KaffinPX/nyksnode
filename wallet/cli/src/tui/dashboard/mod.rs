mod address;
mod balance;
mod send;
mod snapshot;

use std::time::Duration;

use anyhow::Result;
use crossterm::event;
use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use crossterm::event::KeyModifiers;
use nyks_wallet_sdk::wallet::Wallet;
use ratatui::Frame;
use ratatui::layout::Constraint;
use ratatui::layout::Direction;
use ratatui::layout::Layout;
use ratatui::style::Color;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Tabs;
use tokio::sync::mpsc;

use address::AddressPage;
use send::SendPage;
use snapshot::Snapshot;

use crate::tui;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Balance,
    Address,
    Send,
}

impl Tab {
    const ALL: [Tab; 3] = [Tab::Balance, Tab::Address, Tab::Send];

    fn title(self) -> &'static str {
        match self {
            Tab::Balance => "Balance",
            Tab::Address => "Address",
            Tab::Send => "Send",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap()
    }

    fn next(self) -> Tab {
        Tab::ALL[(self.index() + 1) % Tab::ALL.len()]
    }

    fn prev(self) -> Tab {
        let len = Tab::ALL.len();
        Tab::ALL[(self.index() + len - 1) % len]
    }
}

pub async fn run(wallet: Wallet) -> Result<()> {
    let mut terminal = tui::init();
    let result = run_loop(&mut terminal, wallet).await;
    tui::restore();
    result
}

async fn run_loop(terminal: &mut tui::Tui, wallet: Wallet) -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();

    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if tx.send(ev).is_err() {
                break;
            }
        }
    });

    let mut tab = Tab::Balance;
    let mut address_page = AddressPage::default();
    let mut send_page = SendPage::default();
    let mut snapshot = Snapshot::fetch(&wallet).await;
    let mut refresh = tokio::time::interval(Duration::from_secs(5));
    refresh.tick().await;

    terminal.draw(|frame| draw(frame, tab, &address_page, &send_page, &snapshot))?;

    loop {
        // No-op branch when no send is running.
        let send_update = async {
            if send_page.is_active() {
                send_page.await_result().await
            } else {
                std::future::pending().await
            }
        };

        tokio::select! {
            _ = refresh.tick() => {
                snapshot = Snapshot::fetch(&wallet).await;
                terminal.draw(|frame| draw(frame, tab, &address_page, &send_page, &snapshot))?;
            }
            _ = send_update => {
                terminal.draw(|frame| draw(frame, tab, &address_page, &send_page, &snapshot))?;
            }
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else { break };

                match event {
                    Event::Resize(_, _) => {
                        terminal.draw(|frame| draw(frame, tab, &address_page, &send_page, &snapshot))?;
                    }
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                            break;
                        }

                        match key.code {
                            // Block tab switching while a send is proving.
                            KeyCode::Left if !send_page.is_active() => tab = tab.prev(),
                            KeyCode::Right if !send_page.is_active() => tab = tab.next(),
                            // While on Send, everything else belongs to the form.
                            _ if tab == Tab::Send => send_page.handle_key(key.code, &wallet).await,
                            KeyCode::Char('q') | KeyCode::Esc => break,
                            KeyCode::Tab | KeyCode::Char('l') if !send_page.is_active() => tab = tab.next(),
                            KeyCode::BackTab | KeyCode::Char('h') if !send_page.is_active() => tab = tab.prev(),
                            KeyCode::Char('r') => snapshot = Snapshot::fetch(&wallet).await,
                            // Anything else is the active tab's business (e.g. ↑/↓ or c on Address).
                            code if tab == Tab::Address => address_page.handle_key(code, &snapshot),
                            _ => continue,
                        }

                        terminal.draw(|frame| draw(frame, tab, &address_page, &send_page, &snapshot))?;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn draw(
    frame: &mut Frame,
    tab: Tab,
    address_page: &AddressPage,
    send_page: &SendPage,
    snapshot: &Snapshot,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let titles: Vec<Line> = Tab::ALL.iter().map(|t| Line::from(t.title())).collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" nyks-wallet "),
        )
        .select(tab.index())
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, chunks[0]);

    match tab {
        Tab::Balance => balance::draw(frame, chunks[1], snapshot),
        Tab::Address => address_page.draw(frame, chunks[1], snapshot),
        Tab::Send => send_page.draw(frame, chunks[1]),
    }

    let help = match tab {
        Tab::Balance => "Tab/←→ switch tabs · r refresh · q quit",
        Tab::Address => {
            "Tab/←→ switch tabs · ↑/↓ choose address type · c copy · r refresh · q quit"
        }
        Tab::Send if send_page.is_active() => "Sending... please wait · Ctrl-C quit",
        Tab::Send => {
            "←/→ switch tabs · Tab/↓ next field · Enter confirm · Esc clear/back · Ctrl-C quit"
        }
    };
    frame.render_widget(Paragraph::new(help), chunks[2]);
}
