use num_traits::CheckedSub;
use nyks_consensus::network::Network;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::address::Recipient;
use nyks_standards::wallet::keys::key::KeyType;
use nyks_wallet_sdk::wallet::Wallet;

use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use tracing::error;

use std::str::FromStr;

use tokio::sync::mpsc;

use tracing::{info, warn};

#[derive(Debug)]
enum Command {
    Height,
    Balance,
    Address(Option<KeyType>),
    Send {
        recipient: Address,
        amount: NativeCurrencyAmount,
        fee: NativeCurrencyAmount,
    },
    Unknown(String),
}

impl FromStr for Command {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut parts = input.split_whitespace();

        // Empty commands are ignored.
        let cmd = parts.next().unwrap().to_lowercase();

        match cmd.as_str() {
            "height" => Ok(Command::Height),
            "balance" => Ok(Command::Balance),
            "address" => {
                let key_type = match parts.next() {
                    Some("symmetric") => Some(KeyType::Symmetric),
                    Some(_) => Some(KeyType::Generation),
                    None => None,
                };

                Ok(Command::Address(key_type))
            }
            "send" => {
                let recipient_str = parts.next().ok_or("Missing address (e.g. nolgam...)")?;
                let recipient = Address::from_bech32m(recipient_str, Network::Testnet(0))
                    .map_err(|e| format!("Invalid recipient: {e}. Is it on the wrong network?"))?;

                let amount_str = parts.next().ok_or("Missing amount (e.g. 1.6)")?;
                let amount = NativeCurrencyAmount::coins_from_str(amount_str).map_err(|_| {
                    format!("Invalid amount '{amount_str}'. Try using a number (e.g. 1.5).")
                })?;

                let fee_str = parts.next().ok_or("Missing fee (e.g. 0.05)")?;
                let fee = NativeCurrencyAmount::coins_from_str(fee_str).map_err(|_| {
                    format!("Invalid fee '{fee_str}'. Try using a number (e.g. 0.001).")
                })?;

                Ok(Command::Send {
                    recipient,
                    amount,
                    fee,
                })
            }

            other => Ok(Command::Unknown(other.to_string())),
        }
    }
}

pub async fn start_console(wallet: Wallet) {
    info!(
        "Loaded wallet with {} NYKS on height {}.",
        wallet.total_balance().await,
        wallet.height().await
    );

    let (tx, mut rx) = mpsc::unbounded_channel::<Command>();

    tokio::task::spawn_blocking(move || {
        let mut rl = DefaultEditor::new().expect("failed to init rustyline");

        loop {
            match rl.readline("") {
                Ok(line) => {
                    if line.trim().is_empty() {
                        continue;
                    }

                    match line.parse::<Command>() {
                        Ok(cmd) => {
                            if tx.send(cmd).is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            warn!("{err}");
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    std::process::exit(0);
                }
                Err(ReadlineError::Eof) => {
                    break;
                }
                Err(err) => {
                    panic!("unexpected readline error: {:?}", err);
                }
            }
        }
    });

    while let Some(cmd) = rx.recv().await {
        match cmd {
            Command::Height => {
                info!(
                    "Height: {} (chain height {}).",
                    wallet.height().await,
                    wallet.tip_height().await
                );
            }
            Command::Balance => {
                let utxo_count = wallet.utxo_count().await;
                let spendable_balance = wallet.spendable_balance().await;
                let total_balance = wallet.total_balance().await;
                let unconfirmed_balance = wallet.unconfirmed_balance().await;

                info!(
                    "Balance: {} NYKS ({} UTXOs; {} spendable, {} timelocked, {} unconfirmed).",
                    total_balance,
                    utxo_count,
                    spendable_balance,
                    total_balance.checked_sub(&spendable_balance).unwrap(),
                    unconfirmed_balance,
                );
            }
            Command::Address(key_type) => {
                let key_type = key_type.unwrap_or(KeyType::Generation);
                let address = wallet.address(key_type).await;

                println!("\n{}", address.to_bech32m(wallet.network));
            }
            Command::Send {
                recipient,
                amount,
                fee,
            } => {
                info!(
                    "Initiating sending of {} NYKS with fee {} NYKS...",
                    amount, fee
                );

                match wallet.send(recipient, amount, fee).await {
                    Ok(id) => info!("Announced {} successfully.", id),
                    Err(err) => error!("Failed to submit transaction: {}.", err),
                };
            }
            Command::Unknown(cmd) => {
                warn!("Unknown command: {}", cmd);
            }
        }
    }
}
