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
#![deny(unused_crate_dependencies)]

use std::{
    borrow::Cow,
    fs, io,
    time::{SystemTime, UNIX_EPOCH},
};

mod cli;
mod run;
mod util;

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
        log::warn!(
            "Failed to fetch $HOME directory. Falling back to storing everything in memory, \
                meaning that everything will be lost when the node stops. If this is intended, \
                please make this explicit by passing the `--tmp` flag instead."
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

            Some(run::ChainConfig {
                chain_spec: spec_json,
                additional_bootnodes: Vec::new(),
                keystore_memory: Vec::new(),
                sqlite_database_path: base_storage_directory
                    .as_ref()
                    .map(|d| d.join(parsed_relay_spec.id()).join("database")),
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

    // Determine the actual CLI output by replacing `Auto` with the actual value.
    let cli_output = if let cli::Output::Auto = cli_options.output {
        if io::IsTerminal::is_terminal(&io::stderr()) && cli_options.log.is_empty() {
            cli::Output::Informant
        } else {
            cli::Output::Logs
        }
    } else {
        cli_options.output
    };
    debug_assert!(!matches!(cli_output, cli::Output::Auto));

    // Setup the logging system of the binary.
    if !matches!(cli_output, cli::Output::None) {
        let mut builder = env_logger::Builder::new();
        builder.parse_filters("cranelift=error"); // TODO: temporary work around for https://github.com/smol-dot/smoldot/issues/263
        if matches!(cli_output, cli::Output::Informant) {
            // TODO: display infos/warnings in a nicer way ; in particular, immediately put the informant on top of warnings
            builder.filter_level(log::LevelFilter::Info);
        } else {
            builder.filter_level(log::LevelFilter::Debug);
            for filter in &cli_options.log {
                builder.parse_filters(filter);
            }
        }

        if matches!(cli_output, cli::Output::LogsJson) {
            builder.write_style(env_logger::WriteStyle::Never);
            builder.format(|mut formatter, record| {
                // TODO: consider using the "kv" feature of he "logs" crate and output individual fields
                #[derive(serde::Serialize)]
                struct Record<'a> {
                    timestamp: u128,
                    target: &'a str,
                    level: &'static str,
                    message: String,
                }

                serde_json::to_writer(
                    &mut formatter,
                    &Record {
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0),
                        target: record.target(),
                        level: match record.level() {
                            log::Level::Trace => "trace",
                            log::Level::Debug => "debug",
                            log::Level::Info => "info",
                            log::Level::Warn => "warn",
                            log::Level::Error => "error",
                        },
                        message: format!("{}", record.args()),
                    },
                )
                .map_err(|err| io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
                io::Write::write_all(formatter, b"\n")?;
                Ok(())
            });
        } else {
            builder.write_style(match cli_options.color {
                cli::ColorChoice::Always => env_logger::WriteStyle::Always,
                cli::ColorChoice::Never => env_logger::WriteStyle::Never,
            });
        }

        builder.init();
    }

    log::info!("smoldot full node");
    log::info!("Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.");
    log::info!("Copyright (C) 2023  Pierre Krieger.");
    log::info!("This program comes with ABSOLUTELY NO WARRANTY.");
    log::info!(
        "This is free software, and you are welcome to redistribute it under certain conditions."
    );

    // This warning message should be removed if/when the full node becomes mature.
    log::warn!(
        "Please note that this full node is experimental. It is not feature complete and is \
        known to panic often. Please report any panic you might encounter to \
        <https://github.com/smol-dot/smoldot/issues>."
    );

    run::run(run::Config {
        chain: run::ChainConfig {
            chain_spec,
            additional_bootnodes: cli_options
                .additional_bootnode
                .iter()
                .map(|cli::Bootnode { address, peer_id }| (peer_id.clone(), address.clone()))
                .collect(),
            keystore_memory: cli_options.keystore_memory,
            sqlite_database_path,
            keystore_path,
        },
        relay_chain,
        libp2p_key,
        listen_addresses: cli_options.listen_addr,
        json_rpc_address: cli_options.json_rpc_address.0,
        jaeger_agent: cli_options.jaeger,
        show_informant: matches!(cli_output, cli::Output::Informant),
        informant_colors: match cli_options.color {
            cli::ColorChoice::Always => true,
            cli::ColorChoice::Never => false,
        },
    })
    .await
}
