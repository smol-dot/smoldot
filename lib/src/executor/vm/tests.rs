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
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &include_bytes!("./test-polkadot-runtime-v9160.wasm")[..],
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();

        // Note that this test doesn't test much, as anything elaborate would require implementing
        // the Substrate/Polkadot allocator.

        let mut vm = prototype
            .prepare()
            .start(
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
        let module_bytes = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x00, 0x0b,
            0x06, 0x01, 0x00, 0x41, 0x03, 0x0b, 0x00,
        ];

        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes[..],
            exec_hint,
            symbols: &mut |_, _, _| Ok(0)
        })
        .is_err());
    }
}

#[test]
fn has_start_function() {
    for exec_hint in super::ExecHint::available_engines() {
        let module_bytes = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x02, 0x09, 0x01, 0x01, 0x71, 0x03, 0x69, 0x6d, 0x70, 0x00, 0x00, 0x08, 0x01, 0x00,
        ];

        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes[..],
            exec_hint,
            symbols: &mut |_, _, _| Ok(0)
        })
        .is_err());
    }
}

#[test]
fn unsupported_type() {
    for exec_hint in super::ExecHint::available_engines() {
        let module_bytes = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01,
            0x7b, 0x02, 0x0d, 0x01, 0x04, 0x74, 0x65, 0x73, 0x74, 0x04, 0x66, 0x75, 0x6e, 0x63,
            0x00, 0x00,
        ];

        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes[..],
            exec_hint,
            symbols: &mut |_, _, _| Ok(0)
        })
        .is_err());
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
            (i32.const 2)
            i32.add
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();

        let mut vm = prototype.prepare().start("hello", &[]).unwrap();

        let mut resume_value = None;
        loop {
            match vm.run(resume_value) {
                Ok(super::ExecOutcome::Finished {
                    return_value: Ok(value),
                }) => {
                    assert_eq!(value, Some(super::WasmValue::I32(5)));
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
        assert!(matches!(
            super::VirtualMachinePrototype::new(super::Config {
                module_bytes: &module_bytes,
                exec_hint,
                symbols: &mut |_, _, _| Ok(0)
            }),
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
        assert!(matches!(
            super::VirtualMachinePrototype::new(super::Config {
                module_bytes: &module_bytes,
                exec_hint,
                symbols: &mut |_, _, _| Ok(0)
            }),
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
        assert!(matches!(
            super::VirtualMachinePrototype::new(super::Config {
                module_bytes: &module_bytes,
                exec_hint,
                symbols: &mut |_, _, _| Ok(0)
            }),
            Err(super::NewErr::InvalidWasm(_) | super::NewErr::TwoMemories)
        ));
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
        super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
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
        assert!(matches!(
            super::VirtualMachinePrototype::new(super::Config {
                module_bytes: &module_bytes,
                exec_hint,
                symbols: &mut |_, _, _| Err(())
            }),
            Err(super::NewErr::UnresolvedFunctionImport { .. })
        ));
    }
}

#[test]
fn unsupported_signature() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i32) (param f64) (result i32)))
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result i32) i32.const 0)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        assert!(matches!(
            super::VirtualMachinePrototype::new(super::Config {
                module_bytes: &module_bytes,
                exec_hint,
                symbols: &mut |_, _, _| Ok(0)
            }),
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
        assert!(matches!(
            super::VirtualMachinePrototype::new(super::Config {
                module_bytes: &module_bytes,
                exec_hint,
                symbols: &mut |_, _, _| Ok(0)
            }),
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
        // TODO: `Ok(_)` shouldn't be accepted, but wasmtime doesn't really make it possible to detect the start function at the moment
        assert!(matches!(
            super::VirtualMachinePrototype::new(super::Config {
                module_bytes: &module_bytes,
                exec_hint,
                symbols: &mut |_, _, _| Ok(0)
            }),
            Err(super::NewErr::StartFunctionNotSupported) | Ok(_)
        ));
    }
}

#[test]
fn max_memory_pages() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (global $g (export "test") i32 (i32.const 12))
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
        assert_eq!(
            prototype.memory_max_pages().unwrap(),
            super::HeapPages::new(4096)
        );
    }
}

#[test]
fn get_global() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (global $g (export "test") i32 (i32.const 12))
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let mut prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
        assert_eq!(prototype.global_value("test").unwrap(), 12);
    }
}

#[test]
fn call_non_existing_function() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result i32) i32.const 0)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
        assert!(matches!(
            prototype.prepare().start("doesntexist", &[]),
            Err((super::StartErr::FunctionNotFound, _))
        ));
    }
}

#[test]
fn call_signature_not_supported() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result f64) unreachable)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
        assert!(matches!(
            prototype.prepare().start("hello", &[]),
            Err((super::StartErr::SignatureNotSupported, _))
        ));
    }
}

#[test]
fn bad_params_types() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (param i32) (result i32) i32.const 0)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
        assert!(matches!(
            prototype.prepare().start("hello", &[]),
            Err((super::StartErr::InvalidParameters, _))
        ));
    }
}

#[test]
fn try_to_call_global() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (global $g (export "hello") i32 (i32.const 12))
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
        assert!(matches!(
            prototype.prepare().start("hello", &[]),
            // TODO: wasmi doesn't properly detect NotAFunction at the moment
            Err((
                super::StartErr::NotAFunction | super::StartErr::FunctionNotFound,
                _
            ))
        ));
    }
}

#[test]
fn wrong_type_provided_initially() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i32) (result i32)))
        (import "env" "memory" (memory $mem 8 16))
        (func (export "hello") (result i32)
            (call $host_hello (i32.const 3))
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();

        let mut vm = prototype.prepare().start("hello", &[]).unwrap();

        assert!(matches!(
            vm.run(Some(super::WasmValue::I32(3))),
            Err(super::RunErr::BadValueTy { .. })
        ));
    }
}

#[test]
fn wrong_type_returned_by_host_function_call() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i64) (result i32)))
        (import "env" "memory" (memory $mem 8 16))
        (func (export "hello") (result i32)
            (call $host_hello (i64.const 3))
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();

        let mut vm = prototype.prepare().start("hello", &[]).unwrap();

        let Ok(super::ExecOutcome::Interrupted { id: 0, .. }) = vm.run(None) else { panic!() };
        assert!(matches!(
            vm.run(Some(super::WasmValue::I64(3))),
            Err(super::RunErr::BadValueTy { .. })
        ));
    }
}

#[test]
fn memory_min_specified_in_wasm() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 16 4096))
        (func (export "hello") (result i32) i32.const 0)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
        let interpreter = prototype.prepare().start("hello", &[]).unwrap();
        assert_eq!(interpreter.memory_size(), super::HeapPages::new(16));
    }
}

#[test]
fn memory_grow_works() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 16 4096))
        (func (export "hello") (result i32) i32.const 0)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
        let mut interpreter = prototype.prepare().start("hello", &[]).unwrap();
        assert_eq!(interpreter.memory_size(), super::HeapPages::new(16));
        interpreter.grow_memory(super::HeapPages::new(3)).unwrap();
        assert_eq!(interpreter.memory_size(), super::HeapPages::new(19));
    }
}

#[test]
fn memory_grow_detects_limit() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 16 22))
        (func (export "hello") (result i32) i32.const 0)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
        let mut interpreter = prototype.prepare().start("hello", &[]).unwrap();
        assert_eq!(interpreter.memory_size(), super::HeapPages::new(16));
        assert!(interpreter.grow_memory(super::HeapPages::new(10)).is_err());
    }
}

#[test]
fn memory_grow_detects_limit_within_host_function() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "host" "hello" (func $host_hello (param i32) (result i32)))
        (import "env" "memory" (memory $mem 8 16))
        (func (export "hello") (result i32)
            (call $host_hello (i32.const 3))
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();

        let mut vm = prototype.prepare().start("hello", &[]).unwrap();

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
                    assert!(vm.grow_memory(super::HeapPages::new(12)).is_err());
                    resume_value = Some(super::WasmValue::I32(3));
                }
                Ok(super::ExecOutcome::Interrupted { .. }) => panic!(),
                Err(_) => panic!(),
            }
        }
    }
}

//  TODO: re-enable this test if the `mutable-globals` feature is enabled
/*#[test]
fn globals_reinitialized_after_reset() {
    let module_bytes = wat::parse_str(
        r#"
        (module
            (import "env" "memory" (memory $mem 8 16))
            (global $myglob (export "myglob") (mut i32) (i32.const 5))
            (func (export "hello")
                global.get $myglob
                i32.const 1
                i32.add
                global.set $myglob)
        )
        "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let mut prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();
        assert_eq!(prototype.global_value("myglob").unwrap(), 5);

        let mut vm = prototype.prepare().start("hello", &[]).unwrap();
        assert!(matches!(
            vm.run(None),
            Ok(super::ExecOutcome::Finished {
                return_value: Ok(None),
            })
        ));

        let mut prototype = vm.into_prototype();
        assert_eq!(prototype.global_value("myglob").unwrap(), 5);
    }
}*/

#[test]
fn memory_zeroed_after_reset() {
    let module_bytes = wat::parse_str(
        r#"
        (module
            (import "env" "memory" (memory $mem 1024 4096))
            (func (export "hello"))
        )
        "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();

        let mut vm = prototype.prepare();
        vm.write_memory(11, &[5, 6]).unwrap();

        let mut vm = vm.start("hello", &[]).unwrap();
        assert_eq!(vm.read_memory(12, 1).unwrap().as_ref()[0], 6);
        vm.write_memory(12, &[7]).unwrap();
        assert_eq!(vm.read_memory(12, 1).unwrap().as_ref()[0], 7);

        assert!(matches!(
            vm.run(None),
            Ok(super::ExecOutcome::Finished {
                return_value: Ok(None),
            })
        ));

        assert_eq!(vm.read_memory(11, 2).unwrap().as_ref(), &[5, 7]);

        let prototype = vm.into_prototype();
        let vm = prototype.prepare();
        assert_eq!(vm.read_memory(11, 2).unwrap().as_ref(), &[0, 0]);
        assert_eq!(vm.read_memory(12, 1).unwrap().as_ref(), &[0]);

        let vm = vm.start("hello", &[]).unwrap();
        assert_eq!(vm.read_memory(11, 2).unwrap().as_ref(), &[0, 0]);
        assert_eq!(vm.read_memory(12, 1).unwrap().as_ref(), &[0]);
    }
}

#[test]
fn memory_zeroed_after_prepare() {
    let module_bytes = wat::parse_str(
        r#"
        (module
            (import "env" "memory" (memory $mem 1024 4096))
            (func (export "hello"))
        )
        "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        let prototype = super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .unwrap();

        let mut vm = prototype.prepare();
        assert_eq!(vm.read_memory(11, 2).unwrap().as_ref(), &[0, 0]);
        vm.write_memory(11, &[5, 6]).unwrap();

        let vm = vm.into_prototype().prepare();
        assert_eq!(vm.read_memory(11, 2).unwrap().as_ref(), &[0, 0]);
    }
}

#[test]
fn feature_disabled_signext() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result i64)
            (i64.const 2)
            i64.extend32_s
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        // TODO: wasmtime doesn't allow disabling sign-ext /!\ test is faulty /!\ figure out what to do
        // TODO: see https://github.com/paritytech/substrate/issues/10707#issuecomment-1494081313
        if Some(exec_hint) == super::ExecHint::force_wasmtime_if_available() {
            continue;
        }

        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .is_err());
    }
}

#[test]
fn feature_disabled_saturated_float_to_int() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result i64)
            (f32.const 2)
            i64.trunc_sat_f32_s
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        // TODO: wasmtime doesn't allow disabling this feature /!\ test is faulty /!\ figure out what to do
        // TODO: see https://github.com/paritytech/substrate/issues/10707#issuecomment-1494081313
        if Some(exec_hint) == super::ExecHint::force_wasmtime_if_available() {
            continue;
        }

        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .is_err());
    }
}

#[test]
fn feature_disabled_threads() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result i64)
            (atomic.fence)
            i64.const 2
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .is_err());
    }
}

#[test]
fn feature_disabled_reference_type() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result externref) unreachable)
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .is_err());
    }
}

#[test]
fn feature_disabled_bulk_memory() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (result i64)
            (memory.fill (i32.const 0) (i32.const 0) (i32.const 0))
            i64.const 2
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .is_err());
    }
}

#[test]
fn feature_disabled_multi_value() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func (export "hello") (param i64 i64) (result i64 i64 i64)
	        (local.get 0) (local.get 1) (local.get 0)
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .is_err());
    }
}

#[test]
fn feature_disabled_memory64() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem i64 0 4096))
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .is_err());
    }
}

#[test]
fn feature_disabled_mutable_globals() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (global $myglob (export "myglob") (mut i32) (i32.const 5))
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        // TODO: wasmtime doesn't allow disabling this feature /!\ test is faulty /!\ figure out what to do
        // TODO: see https://github.com/paritytech/substrate/issues/10707#issuecomment-1494081313
        if Some(exec_hint) == super::ExecHint::force_wasmtime_if_available() {
            continue;
        }

        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .is_err());
    }
}

#[test]
fn feature_disabled_tail_call() {
    let module_bytes = wat::parse_str(
        r#"
    (module
        (import "env" "memory" (memory $mem 0 4096))
        (func $fac (param $x i64) (result i64)
            (return_call $fac-aux (get_local $x) (i64.const 1))
        )
        (func $fac-aux (param $x i64) (param $r i64) (result i64)
          (if (i64.eqz (get_local $x))
            (then (return (get_local $r)))
            (else
              (return_call $fac-aux
                (i64.sub (get_local $x) (i64.const 1))
                (i64.mul (get_local $x) (get_local $r))
              )
            )
          )
        )
    )
    "#,
    )
    .unwrap();

    for exec_hint in super::ExecHint::available_engines() {
        assert!(super::VirtualMachinePrototype::new(super::Config {
            module_bytes: &module_bytes,
            exec_hint,
            symbols: &mut |_, _, _| Ok(0),
        })
        .is_err());
    }
}

// TODO: check that the SIMD feature is disabled: https://github.com/WebAssembly/simd/blob/master/proposals/simd/SIMD.md
// TODO: check that the extended-const feature is disabled: https://github.com/WebAssembly/extended-const/blob/master/proposals/extended-const/Overview.md

// TODO: test for memory reads and writes, including within host functions
