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
    vm, vm::ExecHint, Config, Error, HeapPages, HostVm, HostVmPrototype, NewErr, StartErr,
};
use super::with_core_version_custom_sections;

#[test]
fn function_to_run_doesnt_exist() {
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
        let host_vm = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        match host_vm.run_no_param("functiondoesntexist") {
            Err((StartErr::VirtualMachine(vm::StartErr::FunctionNotFound), _)) => {}
            _ => unreachable!(),
        }
    }
}

#[test]
fn function_to_run_invalid_params() {
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (import "env" "memory" (memory 0))
        (global (export "__heap_base") i32 (i32.const 0))
        (func (export "hello") (param i32) (result i32) i32.const 0)
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        let host_vm = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        match host_vm.run_no_param("hello") {
            Err((StartErr::VirtualMachine(vm::StartErr::InvalidParameters), _)) => {}
            _ => unreachable!(),
        }
    }
}

#[test]
fn input_provided_correctly() {
    /* Source code:

        #[no_mangle]
        extern "C" fn test(_param_ptr: i32, _param_sz: i32) -> i64 {
            let inparam: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    u32::from_ne_bytes(_param_ptr.to_ne_bytes()) as usize as *const u8,
                    u32::from_ne_bytes(_param_sz.to_ne_bytes()) as usize,
                )
            };

            if inparam
                != b"hello world"
            {
                core::arch::wasm32::unreachable()
            }

            0
        }
    */
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (type (;0;) (func (param i32 i32) (result i32)))
        (type (;1;) (func (param i32 i32) (result i64)))
        (type (;2;) (func (param i32 i32 i32) (result i32)))
        (func (;0;) (type 0) (param i32 i32) (result i32)
          local.get 0
          local.get 1
          i32.const 11
          call 3
          i32.const 0
          i32.ne)
        (func (;1;) (type 1) (param i32 i32) (result i64)
          block  ;; label = @1
            local.get 1
            i32.const 11
            i32.ne
            br_if 0 (;@1;)
            local.get 0
            i32.const 1048576
            call 0
            br_if 0 (;@1;)
            i64.const 0
            return
          end
          unreachable
          unreachable)
        (func (;2;) (type 2) (param i32 i32 i32) (result i32)
          (local i32 i32 i32)
          i32.const 0
          local.set 3
          block  ;; label = @1
            local.get 2
            i32.eqz
            br_if 0 (;@1;)
            block  ;; label = @2
              loop  ;; label = @3
                local.get 0
                i32.load8_u
                local.tee 4
                local.get 1
                i32.load8_u
                local.tee 5
                i32.ne
                br_if 1 (;@2;)
                local.get 0
                i32.const 1
                i32.add
                local.set 0
                local.get 1
                i32.const 1
                i32.add
                local.set 1
                local.get 2
                i32.const -1
                i32.add
                local.tee 2
                i32.eqz
                br_if 2 (;@1;)
                br 0 (;@3;)
              end
            end
            local.get 4
            local.get 5
            i32.sub
            local.set 3
          end
          local.get 3)
        (func (;3;) (type 2) (param i32 i32 i32) (result i32)
          local.get 0
          local.get 1
          local.get 2
          call 2)
        (table (;0;) 1 1 funcref)
        (memory (;0;) 17)
        (global (;0;) (mut i32) (i32.const 1048576))
        (global (;1;) i32 (i32.const 1048587))
        (global (;2;) i32 (i32.const 1048592))
        (export "memory" (memory 0))
        (export "test" (func 1))
        (export "__data_end" (global 1))
        (export "__heap_base" (global 2))
        (data (;0;) (i32.const 1048576) "hello world")
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        let proto = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        let mut vm = HostVm::from(proto.run("test", b"hello world").unwrap());
        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Finished(v) => {
                    assert_eq!(v.value().as_ref(), b"");
                    break;
                }
                _ => unreachable!(),
            }
        }
    }

    for exec_hint in ExecHint::available_engines() {
        let proto = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        let mut vm = HostVm::from(
            proto
                .run_vectored("test", [&b"hello "[..], &b"world"[..]].into_iter())
                .unwrap(),
        );

        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Finished(v) => {
                    assert_eq!(v.value().as_ref(), b"");
                    break;
                }
                _ => unreachable!(),
            }
        }
    }

    for exec_hint in ExecHint::available_engines() {
        let proto = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        let mut vm = HostVm::from(proto.run("test", b"unexpected input").unwrap());
        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Error {
                    error: Error::Trap(_),
                    ..
                } => {
                    break;
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn large_input_provided_correctly() {
    /* Source code:

        #[no_mangle]
        extern "C" fn test(_param_ptr: i32, _param_sz: i32) -> i64 {
            let inparam: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    u32::from_ne_bytes(_param_ptr.to_ne_bytes()) as usize as *const u8,
                    u32::from_ne_bytes(_param_sz.to_ne_bytes()) as usize,
                )
            };

            if inparam.len() != 395718 {
                core::arch::wasm32::unreachable()
            }

            for byte in inparam {
                if *byte != 0x7a {
                    core::arch::wasm32::unreachable()
                }
            }

            0
        }
    */
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"(module
                (type (;0;) (func (param i32 i32) (result i64)))
                (func (;0;) (type 0) (param i32 i32) (result i64)
                  (local i32)
                  block  ;; label = @1
                    block  ;; label = @2
                      local.get 1
                      i32.const 395718
                      i32.ne
                      br_if 0 (;@2;)
                      i32.const 0
                      local.set 1
                      loop  ;; label = @3
                        local.get 1
                        i32.const 395718
                        i32.eq
                        br_if 2 (;@1;)
                        local.get 0
                        local.get 1
                        i32.add
                        local.set 2
                        local.get 1
                        i32.const 1
                        i32.add
                        local.set 1
                        local.get 2
                        i32.load8_u
                        i32.const 122
                        i32.eq
                        br_if 0 (;@3;)
                      end
                    end
                    unreachable
                    unreachable
                  end
                  i64.const 0)
                (table (;0;) 1 1 funcref)
                (memory (;0;) 16)
                (global (;0;) (mut i32) (i32.const 1048576))
                (global (;1;) i32 (i32.const 1048576))
                (global (;2;) i32 (i32.const 1048576))
                (export "memory" (memory 0))
                (export "test" (func 0))
                (export "__data_end" (global 1))
                (export "__heap_base" (global 2))
            )
    "#,
        )
        .unwrap(),
    );

    let input_data = (0..395718).map(|_| 0x7a).collect::<Vec<_>>();

    for exec_hint in ExecHint::available_engines() {
        let proto = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        let mut vm = HostVm::from(proto.run("test", &input_data).unwrap());
        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Finished(v) => {
                    assert_eq!(v.value().as_ref(), b"");
                    break;
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn return_value_works() {
    /* Source code:

        static OUT: &[u8] = b"hello world";

        #[no_mangle]
        extern "C" fn test(_: i32, _: i32) -> i64 {
            let ptr = OUT.as_ptr() as usize as u32;
            let sz = OUT.len() as u32;

            i64::from_ne_bytes((u64::from(sz) << 32 | u64::from(ptr)).to_ne_bytes())
        }
    */
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (type (;0;) (func (param i32 i32) (result i64)))
        (func (;0;) (type 0) (param i32 i32) (result i64)
            i32.const 1048576
            i64.extend_i32_u
            i64.const 47244640256
            i64.or)
        (table (;0;) 1 1 funcref)
        (memory (;0;) 17)
        (global (;0;) (mut i32) (i32.const 1048576))
        (global (;1;) i32 (i32.const 1048587))
        (global (;2;) i32 (i32.const 1048592))
        (export "memory" (memory 0))
        (export "test" (func 0))
        (export "__data_end" (global 1))
        (export "__heap_base" (global 2))
        (data (;0;) (i32.const 1048576) "hello world")
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        let proto = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        let mut vm = HostVm::from(proto.run("test", &[]).unwrap());
        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Finished(out) => {
                    assert_eq!(out.value().as_ref(), b"hello world");
                    break;
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn bad_return_value() {
    /* Source code:

        #[no_mangle]
        extern "C" fn test(_: i32, _: i32) -> i32 {
            0
        }
    */
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (type (;0;) (func (param i32 i32) (result i32)))
        (func (;0;) (type 0) (param i32 i32) (result i32)
            i32.const 0)
        (table (;0;) 1 1 funcref)
        (memory (;0;) 16)
        (global (;0;) (mut i32) (i32.const 1048576))
        (global (;1;) i32 (i32.const 1048576))
        (global (;2;) i32 (i32.const 1048576))
        (export "memory" (memory 0))
        (export "test" (func 0))
        (export "__data_end" (global 1))
        (export "__heap_base" (global 2))
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        let proto = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        let mut vm = HostVm::from(proto.run("test", &[]).unwrap());
        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Error {
                    error: Error::BadReturnValue { .. },
                    ..
                } => {
                    break;
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn returned_ptr_out_of_range() {
    /* Source code:

        #[no_mangle]
        extern "C" fn test(_: i32, _: i32) -> i64 {
            let ptr = 0xffff_fff0usize as u32;
            let sz = 5 as u32;

            i64::from_ne_bytes((u64::from(sz) << 32 | u64::from(ptr)).to_ne_bytes())
        }
    */
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (type (;0;) (func (param i32 i32) (result i64)))
        (func (;0;) (type 0) (param i32 i32) (result i64)
            i64.const 25769803760)
        (table (;0;) 1 1 funcref)
        (memory (;0;) 16)
        (global (;0;) (mut i32) (i32.const 1048576))
        (global (;1;) i32 (i32.const 1048576))
        (global (;2;) i32 (i32.const 1048576))
        (export "memory" (memory 0))
        (export "test" (func 0))
        (export "__data_end" (global 1))
        (export "__heap_base" (global 2))
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        let proto = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        let mut vm = HostVm::from(proto.run("test", &[]).unwrap());
        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Error {
                    error: Error::ReturnedPtrOutOfRange { .. },
                    ..
                } => {
                    break;
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn returned_size_out_of_range() {
    /* Source code:

        #[no_mangle]
        extern "C" fn test(_: i32, _: i32) -> i64 {
            let ptr = 5 as u32;
            let sz = 0xffff_fff0usize as u32;

            i64::from_ne_bytes((u64::from(sz) << 32 | u64::from(ptr)).to_ne_bytes())
        }
    */
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (type (;0;) (func (param i32 i32) (result i64)))
        (func (;0;) (type 0) (param i32 i32) (result i64)
            i64.const -68719476731)
        (table (;0;) 1 1 funcref)
        (memory (;0;) 16)
        (global (;0;) (mut i32) (i32.const 1048576))
        (global (;1;) i32 (i32.const 1048576))
        (global (;2;) i32 (i32.const 1048576))
        (export "memory" (memory 0))
        (export "test" (func 0))
        (export "__data_end" (global 1))
        (export "__heap_base" (global 2))
    )
    "#,
        )
        .unwrap(),
    );

    for exec_hint in ExecHint::available_engines() {
        let proto = HostVmPrototype::new(Config {
            allow_unresolved_imports: false,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        let mut vm = HostVm::from(proto.run("test", &[]).unwrap());
        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Error {
                    error: Error::ReturnedPtrOutOfRange { .. },
                    ..
                } => {
                    break;
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn unresolved_host_function_called() {
    /* Source code:
        extern {
            fn host_function_that_doesnt_exist();
        }

        #[no_mangle]
        extern "C" fn test(_: i32, _: i32) -> i64 {
            unsafe {
                host_function_that_doesnt_exist()
            }

            0
        }
    */
    let module_bytes = with_core_version_custom_sections(
        wat::parse_str(
            r#"
    (module
        (type (;0;) (func))
        (type (;1;) (func (param i32 i32) (result i64)))
        (import "env" "host_function_that_doesnt_exist" (func (;0;) (type 0)))
        (func (;1;) (type 1) (param i32 i32) (result i64)
          call 0
          i64.const 0)
        (table (;0;) 1 1 funcref)
        (memory (;0;) 16)
        (global (;0;) (mut i32) (i32.const 1048576))
        (global (;1;) i32 (i32.const 1048576))
        (global (;2;) i32 (i32.const 1048576))
        (export "memory" (memory 0))
        (export "test" (func 1))
        (export "__data_end" (global 1))
        (export "__heap_base" (global 2))
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
            Err(NewErr::VirtualMachine(vm::NewErr::UnresolvedFunctionImport { .. })) => {}
            _ => panic!(),
        }

        let proto = HostVmPrototype::new(Config {
            allow_unresolved_imports: true,
            exec_hint,
            heap_pages: HeapPages::new(1024),
            module: &module_bytes,
        })
        .unwrap();

        let mut vm = HostVm::from(proto.run("test", &[]).unwrap());
        loop {
            match vm {
                HostVm::ReadyToRun(r) => vm = r.run(),
                HostVm::Error {
                    error: Error::UnresolvedFunctionCalled { .. },
                    ..
                } => {
                    break;
                }
                _ => unreachable!(),
            }
        }
    }
}

// TODO: consider more tests for the other errors here, or add them on a host-function case-by-case basis
