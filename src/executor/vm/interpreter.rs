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

//! Implements the API documented [in the parent module](..).

use super::{
    ExecOutcome, GlobalValueErr, HeapPages, ModuleError, NewErr, OutOfBoundsError, RunErr,
    Signature, StartErr, Trap, ValueType, WasmValue,
};

use alloc::{borrow::ToOwned as _, format, string::ToString as _, sync::Arc, vec::Vec};
use core::fmt;

/// See [`super::Module`].
#[derive(Clone)]
pub struct Module {
    // Note: an `Arc` is used in order to expose the same API as wasmtime does. If in the future
    // wasmtime happened to no longer use internal reference counting, this `Arc` should be
    // removed.
    inner: Arc<wasmi::Module>,
}

impl Module {
    /// See [`super::Module::new`].
    pub fn new(module_bytes: impl AsRef<[u8]>) -> Result<Self, ModuleError> {
        let engine = wasmi::Engine::default(); // TODO: investigate config
        let module = wasmi::Module::new(&engine, module_bytes.as_ref())
            .map_err(|err| ModuleError(err.to_string()))?;

        Ok(Module {
            inner: Arc::new(module),
        })
    }
}

/// See [`super::VirtualMachinePrototype`].
pub struct InterpreterPrototype {
    // TODO: doc
    store: wasmi::Store<()>,

    /// Original module.
    module: Arc<wasmi::Module>,

    /// Linker used to create instances.
    linker: wasmi::Linker<()>,

    /// An instance of the module.
    instance: wasmi::Instance,

    /// Memory of the module instantiation.
    memory: wasmi::Memory,

    /// Table of the indirect function calls.
    ///
    /// In Wasm, function pointers are in reality indices in a table called
    /// `__indirect_function_table`. This is this table, if it exists.
    indirect_table: Option<wasmi::Table>,
}

impl InterpreterPrototype {
    /// See [`super::VirtualMachinePrototype::new`].
    pub fn new(
        module: &Module,
        mut symbols: impl FnMut(&str, &str, &Signature) -> Result<usize, ()>,
    ) -> Result<Self, NewErr> {
        let mut store = wasmi::Store::new(module.inner.engine(), ());

        let mut linker = wasmi::Linker::new();
        let mut import_memory = None;

        for import in module.inner.imports() {
            match import.ty() {
                wasmi::ExternType::Func(func_type) => {
                    let conv_signature = match Signature::try_from(func_type) {
                        Ok(i) => i,
                        Err(_) => {
                            return Err(NewErr::ModuleError(ModuleError(format!(
                                "Function with unsupported signature `{}`:`{}`",
                                import.module(),
                                import.name()
                            ))))
                        }
                    };

                    let function_index =
                        match symbols(import.module(), import.name(), &conv_signature) {
                            Ok(i) => i,
                            Err(_) => {
                                return Err(NewErr::UnresolvedFunctionImport {
                                    module_name: import.module().to_owned(),
                                    function: import.name().to_owned(),
                                })
                            }
                        };

                    let func = wasmi::Func::new(
                        &mut store,
                        func_type.clone(),
                        move |_caller, parameters, _ret| {
                            Err(wasmi::core::Trap::from(InterruptedTrap {
                                function_index,
                                parameters: parameters
                                    .iter()
                                    .map(|v| WasmValue::try_from(v).unwrap())
                                    .collect(),
                            }))
                        },
                    );

                    // `define` returns an error in case of duplicate definition. Since we
                    // enumerate over the imports, this can't happen.
                    linker.define(import.module(), import.name(), func).unwrap();
                }
                wasmi::ExternType::Memory(memory_type) => {
                    if import.module() != "env" || import.name() != "memory" {
                        return Err(NewErr::MemoryNotNamedMemory);
                    }

                    // Considering that the memory can only be "env":"memory", and that each
                    // import has a unique name, this block can't be reached more than once.
                    debug_assert!(import_memory.is_none());

                    let memory = wasmi::Memory::new(&mut store, *memory_type)
                        .map_err(|err| ModuleError(err.to_string()))
                        .map_err(NewErr::ModuleError)?;
                    import_memory = Some(memory.clone());

                    // `define` returns an error in case of duplicate definition. Since we
                    // enumerate over the imports, this can't happen.
                    linker
                        .define(import.module(), import.name(), memory)
                        .unwrap();
                }
                wasmi::ExternType::Global(_) => {
                    return Err(NewErr::ModuleError(ModuleError(
                        "Importing globals is not supported".to_owned(),
                    )))
                }
                wasmi::ExternType::Table(_) => {
                    return Err(NewErr::ModuleError(ModuleError(
                        "Importing tables is not supported".to_owned(),
                    )))
                }
            }
        }

        let instance = linker
            .instantiate(&mut store, &module.inner)
            .unwrap() // TODO: no
            .ensure_no_start(&mut store)
            .map_err(|_| NewErr::StartFunctionNotSupported)?;

        let memory = if let Some(import_memory) = import_memory {
            if instance.get_memory(&store, "memory").is_some() {
                return Err(NewErr::TwoMemories);
            }

            import_memory
        } else if let Some(mem) = instance.get_memory(&store, "memory") {
            // TODO: we don't detect NewErr::MemoryIsntMemory
            mem.clone()
        } else {
            return Err(NewErr::NoMemory);
        };

        let indirect_table =
            if let Some(tbl) = instance.get_table(&store, "__indirect_function_table") {
                // TODO: we don't detect NewErr::IndirectTableIsntTable
                Some(tbl.clone())
            } else {
                None
            };

        Ok(InterpreterPrototype {
            store,
            instance,
            linker,
            module: module.inner.clone(),
            memory,
            indirect_table,
        })
    }

    /// See [`super::VirtualMachinePrototype::global_value`].
    pub fn global_value(&self, name: &str) -> Result<u32, GlobalValueErr> {
        let value = self
            .instance
            .get_global(&self.store, name)
            .ok_or(GlobalValueErr::NotFound)? // TODO: we don't differentiate between "missing" and "invalid"
            .get(&self.store);

        match value {
            wasmi::Value::I32(v) => match u32::try_from(v) {
                Ok(v) => Ok(v),
                Err(_) => Err(GlobalValueErr::Invalid), // Negative value.
            },
            _ => Err(GlobalValueErr::Invalid),
        }
    }

    /// See [`super::VirtualMachinePrototype::memory_max_pages`].
    pub fn memory_max_pages(&self) -> Option<HeapPages> {
        self.memory
            .ty(&self.store)
            .maximum_pages()
            .map(|p| HeapPages(u32::from(p)))
    }

    /// See [`super::VirtualMachinePrototype::start`].
    pub fn start(
        mut self,
        min_memory_pages: HeapPages,
        function_name: &str,
        params: &[WasmValue],
    ) -> Result<Interpreter, (StartErr, Self)> {
        if let Some(to_grow) = min_memory_pages
            .0
            .checked_sub(u32::from(self.memory.current_pages(&self.store)))
        {
            let to_grow = match wasmi::core::Pages::new(to_grow) {
                Some(hp) => hp,
                None => return Err((StartErr::RequiredMemoryTooLarge, self)),
            };

            if self.memory.grow(&mut self.store, to_grow).is_err() {
                return Err((StartErr::RequiredMemoryTooLarge, self));
            }
        }

        let func_to_call = match self.instance.get_func(&self.store, function_name) {
            Some(function) => {
                // Try to convert the signature of the function to call, in order to make sure
                // that the type of parameters and return value are supported.
                let Ok(signature) = Signature::try_from(function.ty(&self.store)) else {
                    return Err((StartErr::SignatureNotSupported, self));
                };

                // Check whether the types of the parameters are correct.
                // This is necessary to do manually because for API purposes the call immediately
                //starts, while in the internal implementation it doesn't actually.
                if params.len() != signature.parameters().len() {
                    return Err((StartErr::InvalidParameters, self));
                }
                for (obtained, expected) in params.iter().zip(signature.parameters()) {
                    if obtained.ty() != *expected {
                        return Err((StartErr::InvalidParameters, self));
                    }
                }

                function
            }
            None => return Err((StartErr::FunctionNotFound, self)), // TODO: we don't differentiate between `FunctionNotFound` and `NotAFunction` here
        };

        let has_output = {
            let func_to_call_ty = func_to_call.ty(&self.store);
            let list = func_to_call_ty.results();
            // We don't support more than one return value. This is enforced by verifying the
            // function signature above.
            debug_assert!(list.len() <= 1);
            !list.is_empty()
        };

        Ok(Interpreter {
            store: self.store,
            module: self.module,
            memory: self.memory,
            linker: self.linker,
            has_output,
            execution: Some(Execution::NotStarted(
                func_to_call,
                params
                    .iter()
                    .map(|v| wasmi::Value::from(*v))
                    .collect::<Vec<_>>(),
            )),
            indirect_table: self.indirect_table,
        })
    }
}

impl fmt::Debug for InterpreterPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("InterpreterPrototype").finish()
    }
}

/// This dummy struct is meant to be converted to a `wasmi::core::Trap` and then back through
/// downcasting, similar to `std::any::Any`.
#[derive(Debug, Clone)]
struct InterruptedTrap {
    function_index: usize,
    parameters: Vec<WasmValue>,
}

impl fmt::Display for InterruptedTrap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Interrupted")
    }
}

impl wasmi::core::HostError for InterruptedTrap {}

/// See [`super::VirtualMachine`].
pub struct Interpreter {
    // TODO: doc
    store: wasmi::Store<()>,

    /// Original module.
    module: Arc<wasmi::Module>,

    /// Memory of the module instantiation.
    memory: wasmi::Memory,

    /// Linker used to create instances.
    linker: wasmi::Linker<()>,

    /// Table of the indirect function calls.
    ///
    /// In Wasm, function pointers are in reality indices in a table called
    /// `__indirect_function_table`. This is this table, if it exists.
    indirect_table: Option<wasmi::Table>,

    /// Execution context of this virtual machine. This notably holds the program counter, state
    /// of the stack, and so on.
    ///
    /// This field is an `Option` because we need to be able to temporarily extract it.
    /// If `None`, the state machine is in a poisoned state and cannot run any code anymore.
    execution: Option<Execution>,

    /// `true` if the function being called as one output. `false` if it has zero output.
    /// This information could also be obtained by looking at the type of the function, but having
    /// a simple extra boolean makes it easier.
    has_output: bool,
}

enum Execution {
    NotStarted(wasmi::Func, Vec<wasmi::Value>),
    Started(wasmi::ResumableInvocation),
}

impl Interpreter {
    /// See [`super::VirtualMachine::run`].
    pub fn run(&mut self, value: Option<WasmValue>) -> Result<ExecOutcome, RunErr> {
        let mut output_storage = if self.has_output {
            Some(wasmi::Value::I32(0))
        } else {
            None
        };

        let outputs_storage_ptr = if let Some(output_storage) = output_storage.as_mut() {
            &mut core::array::from_mut(output_storage)[..]
        } else {
            &mut []
        };

        let result = match self.execution.take() {
            Some(Execution::NotStarted(func, params)) => {
                if let Some(value) = value.as_ref() {
                    return Err(RunErr::BadValueTy {
                        expected: None,
                        obtained: Some(value.ty()),
                    });
                }

                func.call_resumable(&mut self.store, &params, outputs_storage_ptr)
            }
            Some(Execution::Started(func)) => {
                let expected = {
                    let func_type = func.host_func().ty(&self.store);
                    // We don't support functions with more than one result type. This should have
                    // been checked at initialization.
                    debug_assert!(func_type.results().len() <= 1);
                    if let Some(r) = func_type.results().iter().next() {
                        Some(ValueType::try_from(*r).unwrap())
                    } else {
                        None
                    }
                };
                let obtained = value.as_ref().map(|v| v.ty());
                if expected != obtained {
                    return Err(RunErr::BadValueTy { expected, obtained });
                }

                let value = value.map(wasmi::Value::from);
                let inputs = match value.as_ref() {
                    Some(v) => &core::array::from_ref(v)[..],
                    None => &[],
                };

                func.resume(&mut self.store, inputs, outputs_storage_ptr)
            }
            None => return Err(RunErr::Poisoned),
        };

        match result {
            Ok(wasmi::ResumableCall::Finished) => {
                // Because we have checked the signature of the function, we know that this
                // conversion can never fail.
                let return_value = output_storage.map(|r| WasmValue::try_from(r).unwrap());
                Ok(ExecOutcome::Finished {
                    return_value: Ok(return_value),
                })
            }
            Ok(wasmi::ResumableCall::Resumable(next)) => {
                let trap = next.host_error().downcast_ref::<InterruptedTrap>().unwrap();
                let outcome = ExecOutcome::Interrupted {
                    id: trap.function_index,
                    params: trap.parameters.clone(),
                };

                self.execution = Some(Execution::Started(next));
                Ok(outcome)
            }
            Err(err) => Ok(ExecOutcome::Finished {
                return_value: Err(Trap(err.to_string())),
            }),
        }
    }

    /// See [`super::VirtualMachine::memory_size`].
    pub fn memory_size(&self) -> HeapPages {
        HeapPages(u32::from(self.memory.current_pages(&self.store)))
    }

    /// See [`super::VirtualMachine::read_memory`].
    pub fn read_memory(
        &'_ self,
        offset: u32,
        size: u32,
    ) -> Result<impl AsRef<[u8]> + '_, OutOfBoundsError> {
        let offset = usize::try_from(offset).map_err(|_| OutOfBoundsError)?;

        let max = offset
            .checked_add(size.try_into().map_err(|_| OutOfBoundsError)?)
            .ok_or(OutOfBoundsError)?;

        struct AccessOffset<T> {
            access: T,
            offset: usize,
            max: usize,
        }

        impl<T: AsRef<[u8]>> AsRef<[u8]> for AccessOffset<T> {
            fn as_ref(&self) -> &[u8] {
                &self.access.as_ref()[self.offset..self.max]
            }
        }

        let access = self.memory.data(&self.store);
        if max > access.as_ref().len() {
            panic!(); //return Err(OutOfBoundsError);
        }

        Ok(AccessOffset {
            access,
            offset,
            max,
        })
    }

    /// See [`super::VirtualMachine::write_memory`].
    pub fn write_memory(&mut self, offset: u32, value: &[u8]) -> Result<(), OutOfBoundsError> {
        let memory_slice = self.memory.data_mut(&mut self.store);

        let start = usize::try_from(offset)
            .map_err(|_| OutOfBoundsError)
            .unwrap();
        let end = start
            .checked_add(value.len())
            .ok_or(OutOfBoundsError)
            .unwrap();

        if end > memory_slice.len() {
            panic!();
        }

        if !value.is_empty() {
            memory_slice[start..end].copy_from_slice(value);
        }

        Ok(())
    }

    /// See [`super::VirtualMachine::write_memory`].
    pub fn grow_memory(&mut self, additional: HeapPages) -> Result<(), OutOfBoundsError> {
        self.memory
            .grow(
                &mut self.store,
                wasmi::core::Pages::new(additional.0)
                    .ok_or(OutOfBoundsError)
                    .unwrap(),
            )
            .map_err(|_| OutOfBoundsError)
            .unwrap();
        Ok(())
    }

    /// See [`super::VirtualMachine::into_prototype`].
    pub fn into_prototype(mut self) -> InterpreterPrototype {
        // TODO: zero the memory

        // Because we have successfully instantiated the module in the past, there's no reason
        // why instantiating again could fail now and not before.
        let instance = self
            .linker
            .instantiate(&mut self.store, &self.module)
            .unwrap()
            .ensure_no_start(&mut self.store)
            .unwrap();

        InterpreterPrototype {
            store: self.store,
            instance,
            linker: self.linker,
            module: self.module,
            memory: self.memory,
            indirect_table: self.indirect_table,
        }
    }
}

impl fmt::Debug for Interpreter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Interpreter").finish()
    }
}
