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

use super::{vm::ExecHint, Config, HeapPages, HostVm, HostVmPrototype};

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

        let mut vm = proto.run_no_param("Core_version").unwrap().run();
        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Error { error, .. } => panic!("{:?}", error),
                HostVm::Finished(f) => break,
                HostVm::GetMaxLogLevel(r) => vm = r.resume(0),
                _ => unreachable!(),
            }
        }
    }
}
