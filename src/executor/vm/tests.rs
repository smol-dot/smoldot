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

#![cfg(test)]

// Here is a helpful link for the WAT format:
// <https://developer.mozilla.org/en-US/docs/WebAssembly/Understanding_the_text_format>

#[test]
fn is_send() {
    // Makes sure that the virtual machine types implement `Send`.
    fn test<T: Send>() {}
    test::<super::VirtualMachine>();
    test::<super::VirtualMachinePrototype>();
}

#[test]
fn basic_seems_to_work() {
    for exec_hint in super::ExecHint::available_engines() {
        let module = super::Module::new(
            &include_bytes!("./test-polkadot-runtime-v9160.wasm")[..],
            exec_hint,
        )
        .unwrap();

        let prototype = super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)).unwrap();

        // Note that this test doesn't test much, as anything elaborate would require implementing
        // the Substrate/Polkadot allocator.

        let mut vm = prototype
            .start(
                super::HeapPages::new(1024),
                "Core_version",
                &[super::WasmValue::I32(0), super::WasmValue::I32(0)],
            )
            .unwrap();

        loop {
            match vm.run(None) {
                Ok(super::ExecOutcome::Finished {
                    return_value: Ok(_),
                }) => break,
                Ok(super::ExecOutcome::Finished {
                    return_value: Err(_),
                }) => panic!(),
                Ok(super::ExecOutcome::Interrupted { id: 0, .. }) => break,
                Ok(super::ExecOutcome::Interrupted { .. }) => panic!(),
                Err(_) => panic!(),
            }
        }
    }
}

#[test]
fn out_of_memory_access() {
    for exec_hint in super::ExecHint::available_engines() {
        let input = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x00, 0x0b,
            0x06, 0x01, 0x00, 0x41, 0x03, 0x0b, 0x00,
        ];

        let module = super::Module::new(input, exec_hint).unwrap();
        assert!(super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)).is_err());
    }
}

#[test]
fn has_start_function() {
    for exec_hint in super::ExecHint::available_engines() {
        let input = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x02, 0x09, 0x01, 0x01, 0x71, 0x03, 0x69, 0x6d, 0x70, 0x00, 0x00, 0x08, 0x01, 0x00,
        ];

        let module = super::Module::new(input, exec_hint).unwrap();
        assert!(super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)).is_err());
    }
}

#[test]
fn unsupported_type() {
    for exec_hint in super::ExecHint::available_engines() {
        let input = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01,
            0x7b, 0x02, 0x0d, 0x01, 0x04, 0x74, 0x65, 0x73, 0x74, 0x04, 0x66, 0x75, 0x6e, 0x63,
            0x00, 0x00,
        ];

        if let Ok(module) = super::Module::new(input, exec_hint) {
            assert!(super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)).is_err());
        }
    }
}

#[test]
fn basic_host_function_return_value_works() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i32) (result i32)))
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result i32)
            (call $host_hello (i32.const 3))
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let module = super::Module::new(&module_bytes, exec_hint).unwrap();

        let prototype = super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)).unwrap();

        let mut vm = prototype
            .start(super::HeapPages::new(1024), "hello", &[])
            .unwrap();

        let mut resume_value = None;
        loop {
            match vm.run(resume_value) {
                Ok(super::ExecOutcome::Finished {
                    return_value: Ok(value),
                }) => {
                    assert_eq!(value, Some(super::WasmValue::I32(3)));
                    break;
                }
                Ok(super::ExecOutcome::Finished {
                    return_value: Err(_),
                }) => panic!(),
                Ok(super::ExecOutcome::Interrupted { id: 0, params }) => {
                    assert_eq!(params, vec![super::WasmValue::I32(3)]);
                    resume_value = Some(super::WasmValue::I32(3));
                }
                Ok(super::ExecOutcome::Interrupted { .. }) => panic!(),
                Err(_) => panic!(),
            }
        }
    }
}

#[test]
fn no_memory() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i32) (result i32)))
        (func (export "hello") (result i32)
            (call $host_hello (i32.const 3))
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let module = super::Module::new(&module_bytes, exec_hint).unwrap();
        assert!(matches!(
            super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)),
            Err(super::NewErr::NoMemory)
        ));
    }
}

#[test]
fn memory_misnamed() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i32) (result i32)))
        (import "env" "memoryyyyy" (memory $mem 0 4096))
        (func (export "hello") (result i32)
            (call $host_hello (i32.const 3))
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let module = super::Module::new(&module_bytes, exec_hint).unwrap();
        assert!(matches!(
            super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)),
            Err(super::NewErr::MemoryNotNamedMemory)
        ));
    }
}

#[test]
fn two_memories() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i32) (result i32)))
        (import "env" "memory" (memory $mem 0 4096))
        (memory (export "memory") 0 4096)
        (func (export "hello") (result i32)
            (call $host_hello (i32.const 3))
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        // Note that at the moment this module fails to compile altogether because the
        // multi-memory Wasm proposal isn't finalized yet. Even once finalized, we want to deny
        // this feature in smoldot.
        if let Ok(module) = super::Module::new(&module_bytes, exec_hint) {
            assert!(matches!(
                super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)),
                Err(super::NewErr::TwoMemories)
            ));
        }
    }
}

#[test]
fn exported_memory_works() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i32) (result i32)))
        (memory (export "memory") 0 4096)
        (func (export "hello") (result i32)
            (call $host_hello (i32.const 3))
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let module = super::Module::new(&module_bytes, exec_hint).unwrap();
        super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)).unwrap();
    }
}

#[test]
fn unresolved_function() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i32) (result i32)))
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result i32)
            (call $host_hello (i32.const 3))
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let module = super::Module::new(&module_bytes, exec_hint).unwrap();
        assert!(matches!(
            super::VirtualMachinePrototype::new(&module, |_, _, _| Err(())),
            Err(super::NewErr::UnresolvedFunctionImport { .. })
        ));
    }
}

#[test]
fn unsupported_signature() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i32) (param externref) (result i32)))
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result i32) i32.const 0)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let module = super::Module::new(&module_bytes, exec_hint).unwrap();
        assert!(matches!(
            super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)),
            Err(super::NewErr::UnresolvedFunctionImport { .. })
        ));
    }
}

#[test]
fn unsupported_import_type() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "mytable" (table 1 funcref))
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result i32) i32.const 0)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let module = super::Module::new(&module_bytes, exec_hint).unwrap();
        assert!(matches!(
            super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)),
            Err(super::NewErr::ImportTypeNotSupported)
        ));
    }
}

#[test]
fn start_function_forbidden() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func $s)
        (start $s)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let module = super::Module::new(&module_bytes, exec_hint).unwrap();
        // TODO: `Ok(_)` shouldn't be accepted, but wasmtime doesn't really make it possible to detect the start function at the moment
        assert!(matches!(
            super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)),
            Err(super::NewErr::StartFunctionNotSupported) | Ok(_)
        ));
    }
}
