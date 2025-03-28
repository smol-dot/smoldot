// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

#![cfg(test)]

use super::{Config, HeapPages, HostVm, HostVmPrototype, StorageProofSizeBehavior, vm::ExecHint};

mod hash_algorithms;
mod initialization;
mod run;

/*

The Wasm fixtures in the tests have been generated by compiling various Rust codes with the
following compilation options:
> rustc --crate-type cdylib -C opt-level=z --target wasm32-unknown-unknown ./foo.rs

*/

// TODO: test all host functions

/// Adds to the provided Wasm bytecode the custom sections containing the runtime version and
/// runtime APIs, that the module wants to find in the Wasm module.
fn with_core_version_custom_sections(mut wasm: Vec<u8>) -> Vec<u8> {
    let spec_name = "foo".to_string();
    let impl_name = "bar".to_string();
    let authoring_version = 0;
    let spec_version = 0;
    let impl_version = 0;
    let transaction_version = 0;
    let state_version = 0;

    let mut core_version = Vec::new();
    core_version
        .extend_from_slice(crate::util::encode_scale_compact_usize(spec_name.len()).as_ref());
    core_version.extend_from_slice(spec_name.as_bytes());
    core_version
        .extend_from_slice(crate::util::encode_scale_compact_usize(impl_name.len()).as_ref());
    core_version.extend_from_slice(impl_name.as_bytes());
    core_version.extend_from_slice(&u32::to_le_bytes(authoring_version));
    core_version.extend_from_slice(&u32::to_le_bytes(spec_version));
    core_version.extend_from_slice(&u32::to_le_bytes(impl_version));
    core_version.extend_from_slice(crate::util::encode_scale_compact_usize(0).as_ref());
    core_version.extend_from_slice(&u32::to_le_bytes(transaction_version));
    core_version.extend_from_slice(&u8::to_le_bytes(state_version));

    let mut core_version_section = Vec::new();
    core_version_section.extend(crate::util::leb128::encode_usize(b"runtime_version".len()));
    core_version_section.extend_from_slice(b"runtime_version");
    core_version_section.extend_from_slice(&core_version);

    let mut core_apis_section = Vec::new();
    core_apis_section.extend(crate::util::leb128::encode_usize(b"runtime_apis".len()));
    core_apis_section.extend_from_slice(b"runtime_apis");

    wasm.push(0);
    wasm.extend(crate::util::leb128::encode_usize(
        core_version_section.len(),
    ));
    wasm.extend_from_slice(&core_version_section);

    wasm.push(0);
    wasm.extend(crate::util::leb128::encode_usize(core_apis_section.len()));
    wasm.extend_from_slice(&core_apis_section);

    wasm
}

#[test]
fn is_send() {
    fn req<T: Send>() {}
    req::<HostVm>();
}

#[test]
fn basic_core_version() {
    for exec_hint in ExecHint::available_engines() {
        let proto = HostVmPrototype::new(Config {
            module: &include_bytes!("./westend-runtime-v9300.wasm")[..],
            heap_pages: HeapPages::new(2048),
            exec_hint,
            allow_unresolved_imports: true,
        })
        .unwrap();

        let mut vm = proto
            .run_no_param(
                "Core_version",
                StorageProofSizeBehavior::proof_recording_disabled(),
            )
            .unwrap()
            .run();
        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Error { error, .. } => panic!("{error:?}"),
                HostVm::Finished(_) => break,
                HostVm::GetMaxLogLevel(r) => vm = r.resume(0),
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn min_requirements() {
    // This module showcases minimum requirements in order for a Wasm module to be accepted.
    // This test exists mostly here in order to provide a template that can be copied for other
    // tests.
    // Note that this is no way a baseline. It is for example also possible to export the memory
    // instead of importing it, or to provide the runtime version through a runtime call.
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (import "env" "memory" (memory 0))
        (global (export "__heap_base") i32 (i32.const 0))
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();
    }
}

// TODO: test more things
