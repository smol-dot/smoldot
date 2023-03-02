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

use alloc::{borrow::ToOwned as _, string::ToString as _, sync::Arc, vec::Vec};
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
    /// Base components that can be used to recreate a prototype later if desired.
    base_components: BaseComponents,

    // TODO: doc
    store: wasmi::Store<()>,

    /// An instance of the module.
    instance: wasmi::Instance,

    /// Memory of the module instantiation.
    memory: wasmi::Memory,
}

struct BaseComponents {
    module: Arc<wasmi::Module>,

    /// For each import of the module, either `None` if not a function, or `Some` containing the
    /// `usize` of that function.
    resolved_imports: Vec<Option<usize>>,
}

impl InterpreterPrototype {
    /// See [`super::VirtualMachinePrototype::new`].
    pub fn new(
        module: &Module,
        mut symbols: impl FnMut(&str, &str, &Signature) -> Result<usize, ()>,
    ) -> Result<Self, NewErr> {
        let mut resolved_imports = Vec::with_capacity(module.inner.imports().len());
        for import in module.inner.imports() {
            match import.ty() {
                wasmi::ExternType::Func(func_type) => {
                    // Note that if `Signature::try_from` fails, a `UnresolvedFunctionImport` is
                    // also returned. This is because it is not possible for the function to
                    // resolve anyway if its signature can't be represented.
                    let function_index =
                        match Signature::try_from(func_type)
                            .ok()
                            .and_then(|conv_signature| {
                                symbols(import.module(), import.name(), &conv_signature).ok()
                            }) {
                            Some(i) => i,
                            None => {
                                return Err(NewErr::UnresolvedFunctionImport {
                                    module_name: import.module().to_owned(),
                                    function: import.name().to_owned(),
                                })
                            }
                        };

                    resolved_imports.push(Some(function_index));
                }
                wasmi::ExternType::Memory(_) => resolved_imports.push(None),
                wasmi::ExternType::Global(_) | wasmi::ExternType::Table(_) => {
                    return Err(NewErr::ImportTypeNotSupported)
                }
            }
        }

        Self::from_base_components(BaseComponents {
            module: module.inner.clone(),
            resolved_imports,
        })
    }

    fn from_base_components(base_components: BaseComponents) -> Result<Self, NewErr> {
        let mut store = wasmi::Store::new(base_components.module.engine(), ());

        let mut linker = wasmi::Linker::<()>::new();
        let mut import_memory = None;

        for (module_import, resolved_function) in base_components
            .module
            .imports()
            .zip(base_components.resolved_imports.iter())
        {
            match module_import.ty() {
                wasmi::ExternType::Func(func_type) => {
                    let function_index = resolved_function.unwrap();

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
                    linker
                        .define(module_import.module(), module_import.name(), func)
                        .unwrap();
                }
                wasmi::ExternType::Memory(memory_type) => {
                    if module_import.module() != "env" || module_import.name() != "memory" {
                        return Err(NewErr::MemoryNotNamedMemory);
                    }

                    // Considering that the memory can only be "env":"memory", and that each
                    // import has a unique name, this block can't be reached more than once.
                    debug_assert!(import_memory.is_none());

                    let memory = wasmi::Memory::new(&mut store, *memory_type)
                        .map_err(|_| NewErr::CouldntAllocateMemory)?;
                    import_memory = Some(memory);

                    // `define` returns an error in case of duplicate definition. Since we
                    // enumerate over the imports, this can't happen.
                    linker
                        .define(module_import.module(), module_import.name(), memory)
                        .unwrap();
                }
                wasmi::ExternType::Global(_) | wasmi::ExternType::Table(_) => {
                    unreachable!()
                }
            }
        }

        let instance = linker
            .instantiate(&mut store, &base_components.module)
            .map_err(|err| NewErr::Other(err.to_string()))?
            .ensure_no_start(&mut store)
            .map_err(|_| NewErr::StartFunctionNotSupported)?;

        let memory =
            if let Some(wasmi::Extern::Memory(import_memory)) = linker.resolve("env", "memory") {
                if instance.get_memory(&store, "memory").is_some() {
                    return Err(NewErr::TwoMemories);
                }

                import_memory
            } else if let Some(mem) = instance.get_memory(&store, "memory") {
                // TODO: we don't detect NewErr::MemoryIsntMemory
                mem
            } else {
                return Err(NewErr::NoMemory);
            };

        Ok(InterpreterPrototype {
            base_components,
            store,
            instance,
            memory,
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

    /// See [`super::VirtualMachinePrototype::prepare`].
    pub fn prepare(self) -> Prepare {
        Prepare { inner: self }
    }
}

impl fmt::Debug for InterpreterPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("InterpreterPrototype").finish()
    }
}

/// See [`super::Prepare`].
pub struct Prepare {
    inner: InterpreterPrototype,
}

impl Prepare {
    /// See [`super::Prepare::into_prototype`].
    pub fn into_prototype(self) -> InterpreterPrototype {
        // Since creation has succeeded in the past, there is no reason for it to fail now.
        InterpreterPrototype::from_base_components(self.inner.base_components).unwrap()
    }

    /// See [`super::Prepare::memory_size`].
    pub fn memory_size(&self) -> HeapPages {
        HeapPages(u32::from(
            self.inner.memory.current_pages(&self.inner.store),
        ))
    }

    /// See [`super::Prepare::read_memory`].
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

        let access = self.inner.memory.data(&self.inner.store);
        if max > access.as_ref().len() {
            return Err(OutOfBoundsError);
        }

        Ok(AccessOffset {
            access,
            offset,
            max,
        })
    }

    /// See [`super::Prepare::write_memory`].
    pub fn write_memory(&mut self, offset: u32, value: &[u8]) -> Result<(), OutOfBoundsError> {
        let memory_slice = self.inner.memory.data_mut(&mut self.inner.store);

        let start = usize::try_from(offset).map_err(|_| OutOfBoundsError)?;
        let end = start.checked_add(value.len()).ok_or(OutOfBoundsError)?;

        if end > memory_slice.len() {
            return Err(OutOfBoundsError);
        }

        if !value.is_empty() {
            memory_slice[start..end].copy_from_slice(value);
        }

        Ok(())
    }

    /// See [`super::Prepare::write_memory`].
    pub fn grow_memory(&mut self, additional: HeapPages) -> Result<(), OutOfBoundsError> {
        self.inner
            .memory
            .grow(
                &mut self.inner.store,
                wasmi::core::Pages::new(additional.0).ok_or(OutOfBoundsError)?,
            )
            .map_err(|_| OutOfBoundsError)?;
        Ok(())
    }

    /// See [`super::Prepare::start`].
    pub fn start(
        self,
        function_name: &str,
        params: &[WasmValue],
    ) -> Result<Interpreter, (StartErr, InterpreterPrototype)> {
        let func_to_call = match self
            .inner
            .instance
            .get_func(&self.inner.store, function_name)
        {
            Some(function) => {
                // Try to convert the signature of the function to call, in order to make sure
                // that the type of parameters and return value are supported.
                let Ok(signature) = Signature::try_from(function.ty(&self.inner.store)) else {
                    return Err((StartErr::SignatureNotSupported, self.inner));
                };

                // Check whether the types of the parameters are correct.
                // This is necessary to do manually because for API purposes the call immediately
                //starts, while in the internal implementation it doesn't actually.
                if params.len() != signature.parameters().len() {
                    return Err((StartErr::InvalidParameters, self.inner));
                }
                for (obtained, expected) in params.iter().zip(signature.parameters()) {
                    if obtained.ty() != *expected {
                        return Err((StartErr::InvalidParameters, self.inner));
                    }
                }

                function
            }
            None => return Err((StartErr::FunctionNotFound, self.inner)), // TODO: we don't differentiate between `FunctionNotFound` and `NotAFunction` here
        };

        let dummy_output_value = {
            let func_to_call_ty = func_to_call.ty(&self.inner.store);
            let list = func_to_call_ty.results();
            // We don't support more than one return value. This is enforced by verifying the
            // function signature above.
            debug_assert!(list.len() <= 1);
            list.first().map(|item| match *item {
                wasmi::core::ValueType::I32 => wasmi::Value::I32(0),
                wasmi::core::ValueType::I64 => wasmi::Value::I64(0),
                wasmi::core::ValueType::F32 => wasmi::Value::F32(0.0f32.into()),
                wasmi::core::ValueType::F64 => wasmi::Value::F64(0.0.into()),
                _ => unreachable!(),
            })
        };

        Ok(Interpreter {
            base_components: self.inner.base_components,
            store: self.inner.store,
            memory: self.inner.memory,
            dummy_output_value,
            execution: Some(Execution::NotStarted(
                func_to_call,
                params
                    .iter()
                    .map(|v| wasmi::Value::from(*v))
                    .collect::<Vec<_>>(),
            )),
        })
    }
}

impl fmt::Debug for Prepare {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Prepare").finish()
    }
}

/// This dummy struct is meant to be converted to a `wasmi::core::Trap` and then back, similar to
/// `std::any::Any`.
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
    /// Base components that can be used to recreate a prototype later if desired.
    base_components: BaseComponents,

    // TODO: doc
    store: wasmi::Store<()>,

    /// Memory of the module instantiation.
    memory: wasmi::Memory,

    /// Execution context of this virtual machine. This notably holds the program counter, state
    /// of the stack, and so on.
    ///
    /// This field is an `Option` because we need to be able to temporarily extract it.
    /// If `None`, the state machine is in a poisoned state and cannot run any code anymore.
    execution: Option<Execution>,

    /// Where the return value of the execution will be stored.
    /// While this could be regenerated every time `run` is called, it is instead kept in the
    /// `Interpreter` struct for convenience.
    dummy_output_value: Option<wasmi::Value>,
}

enum Execution {
    NotStarted(wasmi::Func, Vec<wasmi::Value>),
    Started(wasmi::ResumableInvocation),
}

impl Interpreter {
    /// See [`super::VirtualMachine::run`].
    pub fn run(&mut self, value: Option<WasmValue>) -> Result<ExecOutcome, RunErr> {
        let outputs_storage_ptr = if let Some(output_storage) = self.dummy_output_value.as_mut() {
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
                    func_type
                        .results()
                        .iter()
                        .next()
                        .map(|r| ValueType::try_from(*r).unwrap())
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
                let return_value = self
                    .dummy_output_value
                    .clone()
                    .map(|r| WasmValue::try_from(r).unwrap());
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
            return Err(OutOfBoundsError);
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

        let start = usize::try_from(offset).map_err(|_| OutOfBoundsError)?;
        let end = start.checked_add(value.len()).ok_or(OutOfBoundsError)?;

        if end > memory_slice.len() {
            return Err(OutOfBoundsError);
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
                wasmi::core::Pages::new(additional.0).ok_or(OutOfBoundsError)?,
            )
            .map_err(|_| OutOfBoundsError)?;
        Ok(())
    }

    /// See [`super::VirtualMachine::into_prototype`].
    pub fn into_prototype(self) -> InterpreterPrototype {
        // Since creation has succeeded in the past, there is no reason for it to fail now.
        InterpreterPrototype::from_base_components(self.base_components).unwrap()
    }
}

impl fmt::Debug for Interpreter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Interpreter").finish()
    }
}
