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

use super::super::{
    vm, vm::ExecHint, Config, HeapPages, HostVmPrototype, ModuleFormatError, NewErr,
};
use super::with_core_version_custom_sections;

#[test]
fn invalid_wasm() {
    let module_bytes = &[5, 6, 7, 8, 9, 10];

    for exec_hint in ExecHint::available_engines() {
        match HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        }) {
            Err(NewErr::InvalidWasm(_)) => {}
            _ => panic!(),
        }
    }
}

#[test]
fn invalid_zstd() {
    let module_bytes = &[82, 188, 83, 118, 70, 219, 142, 5, 6, 7, 8, 9, 10];

    for exec_hint in ExecHint::available_engines() {
        match HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        }) {
            Err(NewErr::BadFormat(ModuleFormatError::InvalidZstd)) => {}
            _ => panic!(),
        }
    }
}

#[test]
fn valid_zstd() {
    // This is a basic zstd-compressed Wasm module, with the Substrate-specific ZSTD magic number
    // in front.
    let module_bytes = &[
        82, 188, 83, 118, 70, 219, 142, 5, 40, 181, 47, 253, 36, 109, 181, 2, 0, 50, 197, 18, 25,
        144, 135, 13, 122, 232, 155, 145, 241, 185, 162, 153, 81, 5, 153, 131, 230, 210, 156, 69,
        219, 162, 218, 18, 233, 3, 173, 12, 68, 129, 51, 22, 104, 151, 128, 214, 170, 230, 60, 46,
        85, 25, 214, 129, 147, 224, 47, 217, 88, 156, 129, 89, 184, 59, 150, 0, 231, 131, 39, 204,
        152, 159, 32, 120, 53, 213, 28, 43, 139, 37, 242, 223, 180, 241, 1, 2, 0, 79, 17, 216, 120,
        224, 12, 143, 94, 27, 50,
    ];

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

#[test]
fn no_heap_base() {
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (import "env" "memory" (memory 0))
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        match HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        }) {
            Err(NewErr::HeapBaseNotFound) => {}
            _ => panic!(),
        }
    }
}

#[test]
fn memory_max_size_too_low() {
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (import "env" "memory" (memory 0 1023))
        (global (export "__heap_base") i32 (i32.const 0))
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        match HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        }) {
            Err(NewErr::MemoryMaxSizeTooLow) => {}
            _ => panic!(),
        }
    }
}

#[test]
fn unresolved_host_functions_setting() {
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (import "env" "memory" (memory 0))
        (import "env" "thishostfunctiondoesntexist" (func (param i64) (result i64)))
        (global (export "__heap_base") i32 (i32.const 0))
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        match HostVmPrototype::new(Config {
            allow_unresolved_imports: true,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        }) {
            Ok(_) => {}
            _ => panic!(),
        }

        match HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        }) {
            Err(NewErr::VirtualMachine(vm::NewErr::UnresolvedFunctionImport { .. })) => {}
            _ => panic!(),
        }
    }
}

#[test]
fn host_function_bad_signature() {
    // The `ext_allocator_malloc_version_1` host function exists but its actual signature
    // is `(i32) -> i32`.
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (import "env" "memory" (memory 0))
        (import "env" "ext_allocator_malloc_version_1" (func (param i64) (result i64)))
        (global (export "__heap_base") i32 (i32.const 0))
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        match HostVmPrototype::new(Config {
            allow_unresolved_imports: true,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        }) {
            Ok(_) => {}
            _ => panic!(),
        }

        match HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        }) {
            Err(NewErr::VirtualMachine(vm::NewErr::UnresolvedFunctionImport { .. })) => {}
            _ => panic!(),
        }
    }
}

// TODO: add tests for the runtime version gathering after clarifying the errors in host.rs
