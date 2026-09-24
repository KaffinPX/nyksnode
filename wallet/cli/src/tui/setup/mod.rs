mod create;
mod import;
mod layout;
mod menu;

use anyhow::Result;
use anyhow::bail;
use crossterm::event;
use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use crossterm::event::KeyModifiers;
use nyks_wallet_core::entropy::wallet_entropy::WalletEntropy;
use ratatui::Frame;

use create::CreatePage;
use import::ImportPage;
use menu::MenuPage;

use crate::core::storage::Storage;
use crate::tui;

enum Screen {
    Menu(MenuPage),
    Create(CreatePage),
    Import(ImportPage),
}

/// Runs the interactive "no wallet yet" onboarding flow.
///
/// Returns `Err` if the user quits (`q` / `Esc` at the menu, or `Ctrl-C`
/// anywhere) before finishing.
pub fn run(storage: &Storage) -> Result<WalletEntropy> {
    let mut terminal = tui::init();
    let result = run_loop(&mut terminal, storage);
    tui::restore();
    result
}

fn run_loop(terminal: &mut tui::Tui, storage: &Storage) -> Result<WalletEntropy> {
    let mut screen = Screen::Menu(MenuPage::default());

    loop {
        terminal.draw(|frame| draw(frame, &screen))?;

        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            bail!("setup cancelled");
        }

        match &mut screen {
            Screen::Menu(page) => match page.handle_key(key.code)? {
                menu::Outcome::Stay => {}
                menu::Outcome::GoToCreate => screen = Screen::Create(CreatePage::generate()?),
                menu::Outcome::GoToImport => screen = Screen::Import(ImportPage::default()),
            },
            Screen::Create(page) => match page.handle_key(key.code)? {
                create::Outcome::Stay => {}
                create::Outcome::Back => screen = Screen::Menu(MenuPage::default()),
                create::Outcome::Confirmed { entropy, phrase } => {
                    storage.keys.set_mnemonic(&phrase);
                    return Ok(entropy);
                }
            },
            Screen::Import(page) => match page.handle_key(key.code) {
                import::Outcome::Stay => {}
                import::Outcome::Back => screen = Screen::Menu(MenuPage::default()),
                import::Outcome::Confirmed { entropy, phrase } => {
                    storage.keys.set_mnemonic(&phrase);
                    return Ok(entropy);
                }
            },
        }
    }
}

fn draw(frame: &mut Frame, screen: &Screen) {
    match screen {
        Screen::Menu(page) => page.draw(frame),
        Screen::Create(page) => page.draw(frame),
        Screen::Import(page) => page.draw(frame),
    }
}
