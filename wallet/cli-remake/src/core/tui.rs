/// Terminal handle shared by every screen in this module.
pub type Tui = ratatui::DefaultTerminal;

/// Puts the terminal into raw + alternate-screen mode and returns a
/// ready-to-draw-on terminal handle.
pub fn init() -> Tui {
    ratatui::init()
}

/// Restores the terminal to its normal (cooked, main-screen) state. Always
/// call this before returning out of a TUI screen — including on the error
/// path — so a bad exit never leaves the user's shell in raw mode.
pub fn restore() {
    ratatui::restore();
}
