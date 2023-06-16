// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![deny(rustdoc::broken_intra_doc_links)]
// TODO: #![deny(unused_crate_dependencies)] doesn't work because some deps are used only by the library, figure if this can be fixed?

use std::{
    borrow::Cow,
    fs, io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

mod cli;

fn main() {
    smol::block_on(async_main())
}

async fn async_main() {
    match <cli::CliOptions as clap::Parser>::parse().command {
        cli::CliOptionsCommand::Run(r) => run(*r).await,
        cli::CliOptionsCommand::Blake264BitsHash(opt) => {
            let hash = blake2_rfc::blake2b::blake2b(8, &[], opt.payload.as_bytes());
            println!("0x{}", hex::encode(hash));
        }
    }
}

async fn run(cli_options: cli::CliOptionsRun) {
    // Determine the actual CLI output by replacing `Auto` with the actual value.
    let cli_output = if let cli::Output::Auto = cli_options.output {
        if io::IsTerminal::is_terminal(&io::stderr()) && cli_options.log_level.is_none() {
            cli::Output::Informant
        } else {
            cli::Output::Logs
        }
    } else {
        cli_options.output
    };
    debug_assert!(!matches!(cli_output, cli::Output::Auto));

    // Setup the logging system of the binary.
    let log_callback: Arc<dyn smoldot_full_node::LogCallback + Send + Sync> = match cli_output {
        cli::Output::None => Arc::new(|_level, _message| {}),
        cli::Output::Informant | cli::Output::Logs => {
            let color_choice = cli_options.color.clone();
            let log_level = cli_options.log_level.clone().unwrap_or(cli::LogLevel::Info);
            Arc::new(move |level, message| {
                match (&level, &log_level) {
                    (_, cli::LogLevel::Off) => return,
                    (
                        smoldot_full_node::LogLevel::Warn
                        | smoldot_full_node::LogLevel::Info
                        | smoldot_full_node::LogLevel::Debug
                        | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Error,
                    ) => return,
                    (
                        smoldot_full_node::LogLevel::Info
                        | smoldot_full_node::LogLevel::Debug
                        | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Warn,
                    ) => return,
                    (
                        smoldot_full_node::LogLevel::Debug | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Info,
                    ) => return,
                    (smoldot_full_node::LogLevel::Trace, cli::LogLevel::Debug) => return,
                    _ => {}
                }

                let when = humantime::format_rfc3339_millis(SystemTime::now());

                let level_str = match (level, &color_choice) {
                    (smoldot_full_node::LogLevel::Trace, cli::ColorChoice::Never) => "trace",
                    (smoldot_full_node::LogLevel::Trace, cli::ColorChoice::Always) => {
                        "\x1b[36mtrace\x1b[0m"
                    }
                    (smoldot_full_node::LogLevel::Debug, cli::ColorChoice::Never) => "debug",
                    (smoldot_full_node::LogLevel::Debug, cli::ColorChoice::Always) => {
                        "\x1b[34mdebug\x1b[0m"
                    }
                    (smoldot_full_node::LogLevel::Info, cli::ColorChoice::Never) => "info",
                    (smoldot_full_node::LogLevel::Info, cli::ColorChoice::Always) => {
                        "\x1b[32minfo\x1b[0m"
                    }
                    (smoldot_full_node::LogLevel::Warn, cli::ColorChoice::Never) => "warn",
                    (smoldot_full_node::LogLevel::Warn, cli::ColorChoice::Always) => {
                        "\x1b[33;1mwarn\x1b[0m"
                    }
                    (smoldot_full_node::LogLevel::Error, cli::ColorChoice::Never) => "error",
                    (smoldot_full_node::LogLevel::Error, cli::ColorChoice::Always) => {
                        "\x1b[31;1merror\x1b[0m"
                    }
                };

                eprintln!("[{}] [{}] {}", when, level_str, message);
            }) as Arc<dyn smoldot_full_node::LogCallback + Send + Sync>
        }
        cli::Output::LogsJson => {
            let log_level = cli_options.log_level.clone().unwrap_or(cli::LogLevel::Info);
            Arc::new(move |level, message| {
                match (&level, &log_level) {
                    (_, cli::LogLevel::Off) => return,
                    (
                        smoldot_full_node::LogLevel::Warn
                        | smoldot_full_node::LogLevel::Info
                        | smoldot_full_node::LogLevel::Debug
                        | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Error,
                    ) => return,
                    (
                        smoldot_full_node::LogLevel::Info
                        | smoldot_full_node::LogLevel::Debug
                        | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Warn,
                    ) => return,
                    (
                        smoldot_full_node::LogLevel::Debug | smoldot_full_node::LogLevel::Trace,
                        cli::LogLevel::Info,
                    ) => return,
                    (smoldot_full_node::LogLevel::Trace, cli::LogLevel::Debug) => return,
                    _ => {}
                }

                #[derive(serde::Serialize)]
                struct Record {
                    timestamp: u128,
                    level: &'static str,
                    message: String,
                }

                let mut lock = std::io::stderr().lock();
                if serde_json::to_writer(
                    &mut lock,
                    &Record {
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0),
                        level: match level {
                            smoldot_full_node::LogLevel::Trace => "trace",
                            smoldot_full_node::LogLevel::Debug => "debug",
                            smoldot_full_node::LogLevel::Info => "info",
                            smoldot_full_node::LogLevel::Warn => "warn",
                            smoldot_full_node::LogLevel::Error => "error",
                        },
                        message,
                    },
                )
                .is_ok()
                {
                    let _ = io::Write::write_all(&mut lock, b"\n");
                }
            })
        }
        cli::Output::Auto => unreachable!(), // Handled above.
    };

    let chain_spec: Cow<[u8]> = match &cli_options.chain {
        cli::CliChain::Polkadot => {
            (&include_bytes!("../../demo-chain-specs/polkadot.json")[..]).into()
        }
        cli::CliChain::Kusama => (&include_bytes!("../../demo-chain-specs/kusama.json")[..]).into(),
        cli::CliChain::Westend => {
            (&include_bytes!("../../demo-chain-specs/westend.json")[..]).into()
        }
        cli::CliChain::Custom(path) => fs::read(path).expect("Failed to read chain specs").into(),
    };

    let parsed_chain_spec = {
        smoldot::chain_spec::ChainSpec::from_json_bytes(&chain_spec)
            .expect("Failed to decode chain specification")
    };

    // Directory where we will store everything on the disk, such as the database, secret keys,
    // etc.
    let base_storage_directory = if cli_options.tmp {
        None
    } else if let Some(base) = directories::ProjectDirs::from("io", "smoldot", "smoldot") {
        Some(base.data_dir().to_owned())
    } else {
        log_callback.log(
            smoldot_full_node::LogLevel::Warn,
            "Failed to fetch $HOME directory. Falling back to storing everything in memory, \
                meaning that everything will be lost when the node stops. If this is intended, \
                please make this explicit by passing the `--tmp` flag instead."
                .to_string(),
        );
        None
    };

    // Directory supposed to contain the database.
    let sqlite_database_path = base_storage_directory
        .as_ref()
        .map(|d| d.join(parsed_chain_spec.id()).join("database"));
    // Directory supposed to contain the keystore.
    let keystore_path = base_storage_directory
        .as_ref()
        .map(|path| path.join(parsed_chain_spec.id()).join("keys"));

    // Build the relay chain information if relevant.
    let relay_chain =
        if let Some((relay_chain_name, _parachain_id)) = parsed_chain_spec.relay_chain() {
            let spec_json: Cow<[u8]> = match &cli_options.chain {
                cli::CliChain::Custom(parachain_path) => {
                    // TODO: this is a bit of a hack
                    let relay_chain_path = parachain_path
                        .parent()
                        .unwrap()
                        .join(format!("{relay_chain_name}.json"));
                    fs::read(&relay_chain_path)
                        .expect("Failed to read relay chain specs")
                        .into()
                }
                _ => panic!("Unexpected relay chain specified in hard-coded specs"),
            };

            let parsed_relay_spec = smoldot::chain_spec::ChainSpec::from_json_bytes(&spec_json)
                .expect("Failed to decode relay chain chain specs");

            // Make sure we're not accidentally opening the same chain twice, otherwise weird
            // interactions will happen.
            assert_ne!(parsed_relay_spec.id(), parsed_chain_spec.id());

            Some(smoldot_full_node::ChainConfig {
                chain_spec: spec_json,
                additional_bootnodes: Vec::new(),
                keystore_memory: Vec::new(),
                sqlite_database_path: base_storage_directory
                    .as_ref()
                    .map(|d| d.join(parsed_relay_spec.id()).join("database")),
                sqlite_cache_size: cli_options.relay_chain_database_cache_size.0,
                keystore_path: base_storage_directory
                    .as_ref()
                    .map(|path| path.join(parsed_relay_spec.id()).join("keys")),
            })
        } else {
            None
        };

    // Determine which networking key to use.
    //
    // This is either passed as a CLI option, loaded from disk, or generated randomly.
    let libp2p_key = if let Some(node_key) = &cli_options.libp2p_key {
        *node_key
    } else if let Some(dir) = base_storage_directory.as_ref() {
        let path = dir.join("libp2p_ed25519_secret_key.secret");
        let libp2p_key = if path.exists() {
            let file_content =
                fs::read_to_string(&path).expect("failed to read libp2p secret key file content");
            let hex_decoded =
                hex::decode(file_content).expect("invalid libp2p secret key file content");
            <[u8; 32]>::try_from(hex_decoded).expect("invalid libp2p secret key file content")
        } else {
            let actual_key: [u8; 32] = rand::random();
            fs::write(&path, hex::encode(actual_key))
                .expect("failed to write libp2p secret key file");
            actual_key
        };
        // On Unix platforms, set the permission as 0o400 (only reading and by owner is permitted).
        // TODO: do something equivalent on Windows
        #[cfg(unix)]
        let _ = fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o400));
        libp2p_key
    } else {
        rand::random()
    };

    // Print some general information.
    log_callback.log(
        smoldot_full_node::LogLevel::Info,
        "smoldot full node".to_string(),
    );
    log_callback.log(
        smoldot_full_node::LogLevel::Info,
        "Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.".to_string(),
    );
    log_callback.log(
        smoldot_full_node::LogLevel::Info,
        "Copyright (C) 2023  Pierre Krieger.".to_string(),
    );
    log_callback.log(
        smoldot_full_node::LogLevel::Info,
        "This program comes with ABSOLUTELY NO WARRANTY.".to_string(),
    );
    log_callback.log(
        smoldot_full_node::LogLevel::Info,
        "This is free software, and you are welcome to redistribute it under certain conditions."
            .to_string(),
    );

    // This warning message should be removed if/when the full node becomes mature.
    log_callback.log(
        smoldot_full_node::LogLevel::Warn,
        "Please note that this full node is experimental. It is not feature complete and is \
        known to panic often. Please report any panic you might encounter to \
        <https://github.com/smol-dot/smoldot/issues>."
            .to_string(),
    );

    // Starting from here, a SIGINT (or equivalent) handler is setup. If the user does Ctrl+C,
    // a message will be sent on `ctrlc_rx`.
    // This should be performed after all the expensive initialization is done, as otherwise these
    // expensive initializations aren't interrupted by Ctrl+C, which could be frustrating for the
    // user.
    let ctrlc_detected = {
        let event = event_listener::Event::new();
        let listen = event.listen();
        if let Err(err) = ctrlc::set_handler(move || {
            event.notify(usize::max_value());
        }) {
            // It is not critical to fail to setup the Ctrl-C handler.
            log_callback.log(
                smoldot_full_node::LogLevel::Warn,
                format!("ctrlc-handler-setup-fail; err={err}"),
            );
        }
        listen
    };

    smoldot_full_node::run_until(
        smoldot_full_node::Config {
            chain: smoldot_full_node::ChainConfig {
                chain_spec,
                additional_bootnodes: cli_options
                    .additional_bootnode
                    .iter()
                    .map(|cli::Bootnode { address, peer_id }| (peer_id.clone(), address.clone()))
                    .collect(),
                keystore_memory: cli_options.keystore_memory,
                sqlite_database_path,
                sqlite_cache_size: cli_options.database_cache_size.0,
                keystore_path,
            },
            relay_chain,
            libp2p_key,
            listen_addresses: cli_options.listen_addr,
            json_rpc_address: cli_options.json_rpc_address.0,
            log_callback,
            jaeger_agent: cli_options.jaeger,
            show_informant: matches!(cli_output, cli::Output::Informant),
            informant_colors: match cli_options.color {
                cli::ColorChoice::Always => true,
                cli::ColorChoice::Never => false,
            },
        },
        Box::pin(ctrlc_detected),
    )
    .await
}
