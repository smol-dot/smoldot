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
    ExecOutcome, GlobalValueErr, HeapPages, NewErr, OutOfBoundsError, RunErr, Signature, StartErr,
    Trap, ValueType, WasmValue,
};

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{fmt, future, mem, pin, ptr, slice, task};
// TODO: we use std::sync::Mutex rather than parking_lot::Mutex due to issues with Cargo features, see <https://github.com/paritytech/smoldot/issues/2732>
use std::sync::Mutex;

/// See [`super::VirtualMachinePrototype`].
pub struct JitPrototype {
    /// Base components that can be used to recreate a prototype later if desired.
    base_components: BaseComponents,

    store: wasmtime::Store<()>,

    /// Instantiated Wasm VM.
    instance: wasmtime::Instance,

    /// Shared between the "outside" and the external functions. See [`Shared`].
    shared: Arc<Mutex<Shared>>,

    /// Reference to the memory used by the module.
    memory: wasmtime::Memory,

    /// The type associated with [`JitPrototype`].
    memory_type: wasmtime::MemoryType,
}

struct BaseComponents {
    module: wasmtime::Module,

    /// For each import of the module, either `None` if not a function, or `Some` containing the
    /// `usize` of that function.
    resolved_imports: Vec<Option<usize>>,
}

impl JitPrototype {
    /// See [`super::VirtualMachinePrototype::new`].
    pub fn new(
        module_bytes: &[u8],
        symbols: &mut dyn FnMut(&str, &str, &Signature) -> Result<usize, ()>,
    ) -> Result<Self, NewErr> {
        let mut config = wasmtime::Config::new();
        config.cranelift_nan_canonicalization(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);
        config.async_support(true);
        // The default value of `wasm_backtrace_details` is `Environment`, which reads the
        // `WASMTIME_BACKTRACE_DETAILS` environment variable to determine whether or not to keep
        // debug info. However we don't want any of the behaviour of our code to rely on any
        // environment variables whatsoever. Whether to use `Enable` or `Disable` below isn't
        // very important, so long as it is not `Environment`.
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);

        // Disable all post-MVP wasm features.
        // Some of these configuration options are `true` by default while some others are `false`
        // by default, but we just disable them all to be sure.
        config.wasm_threads(false);
        config.wasm_reference_types(false);
        config.wasm_function_references(false);
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);
        config.wasm_bulk_memory(false);
        config.wasm_multi_value(false);
        config.wasm_multi_memory(false);
        config.wasm_memory64(false);
        config.wasm_tail_call(false);

        let engine =
            wasmtime::Engine::new(&config).map_err(|err| NewErr::InvalidWasm(err.to_string()))?;

        let module = wasmtime::Module::from_binary(&engine, module_bytes)
            .map_err(|err| NewErr::InvalidWasm(err.to_string()))?;

        // Building the list of imports that the Wasm VM is able to use.
        let resolved_imports = {
            let mut imports = Vec::with_capacity(module.imports().len());
            for import in module.imports() {
                match import.ty() {
                    wasmtime::ExternType::Func(func_type) => {
                        // Note that if `Signature::try_from` fails, a `UnresolvedFunctionImport` is
                        // also returned. This is because it is not possible for the function to
                        // resolve anyway if its signature can't be represented.
                        let function_index =
                            match Signature::try_from(&func_type)
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

                        imports.push(Some(function_index));
                    }
                    wasmtime::ExternType::Global(_) | wasmtime::ExternType::Table(_) => {
                        return Err(NewErr::ImportTypeNotSupported);
                    }
                    wasmtime::ExternType::Memory(_) => {
                        imports.push(None);
                    }
                };
            }
            imports
        };

        Self::from_base_components(BaseComponents {
            module,
            resolved_imports,
        })
    }

    fn from_base_components(base_components: BaseComponents) -> Result<Self, NewErr> {
        let mut store = wasmtime::Store::new(base_components.module.engine(), ());

        let mut imported_memory = None;
        let shared = Arc::new(Mutex::new(Shared::ExecutingStart));

        // Building the list of symbols that the Wasm VM is able to use.
        let imports = {
            let mut imports = Vec::with_capacity(base_components.module.imports().len());
            for (module_import, resolved_function) in base_components
                .module
                .imports()
                .zip(base_components.resolved_imports.iter())
            {
                match module_import.ty() {
                    wasmtime::ExternType::Func(func_type) => {
                        let function_index = resolved_function.unwrap();
                        let shared = shared.clone();

                        // Obtain `expected_return_ty`. We know that the type is supported due to
                        // the signature check earlier.
                        let expected_return_ty = func_type
                            .results()
                            .next()
                            .map(|v| ValueType::try_from(v).unwrap());

                        imports.push(wasmtime::Extern::Func(wasmtime::Func::new_async(
                            &mut store,
                            func_type,
                            move |mut caller, params, ret_val| {
                                // This closure is executed whenever the Wasm VM calls a
                                // host function.
                                // While a function call is in progress, only this closure can
                                // have access to the `wasmtime::Store`. For this reason, we use
                                // a small communication protocol with the outside.

                                // Transition `shared` from `OutsideFunctionCall` to
                                // `EnteredFunctionCall`.
                                {
                                    let mut shared_lock = shared.try_lock().unwrap();
                                    match mem::replace(&mut *shared_lock, Shared::Poisoned) {
                                        Shared::OutsideFunctionCall { memory } => {
                                            *shared_lock = Shared::EnteredFunctionCall {
                                                function_index,
                                                // Because the function signature has been
                                                // validated at initialization, we can safely
                                                // convert all the parameter types.
                                                parameters: params
                                                    .iter()
                                                    .map(TryFrom::try_from)
                                                    .collect::<Result<_, _>>()
                                                    .unwrap(),
                                                expected_return_ty,
                                                in_interrupted_waker: None, // Filled below
                                                memory: SliceRawParts(
                                                    memory.data_ptr(&caller),
                                                    memory.data_size(&caller),
                                                ),
                                            };
                                        }
                                        Shared::ExecutingStart => {
                                            return Box::new(future::ready(Err(
                                                wasmtime::Error::new(
                                                    NewErr::StartFunctionNotSupported,
                                                ),
                                            )));
                                        }
                                        _ => unreachable!(),
                                    }
                                }

                                // Return a future that is ready whenever `Shared` contains
                                // `Return`.
                                let shared = shared.clone();
                                Box::new(future::poll_fn(move |cx| {
                                    let mut shared_lock = shared.try_lock().unwrap();
                                    match *shared_lock {
                                        Shared::EnteredFunctionCall {
                                            ref mut in_interrupted_waker,
                                            ..
                                        }
                                        | Shared::WithinFunctionCall {
                                            ref mut in_interrupted_waker,
                                            ..
                                        } => {
                                            *in_interrupted_waker = Some(cx.waker().clone());
                                            task::Poll::Pending
                                        }
                                        Shared::MemoryGrowRequired {
                                            ref memory,
                                            additional,
                                        } => {
                                            // The outer call has made sure that `additional`
                                            // would fit.
                                            memory.grow(&mut caller, additional).unwrap();
                                            *shared_lock = Shared::WithinFunctionCall {
                                                in_interrupted_waker: Some(cx.waker().clone()),
                                                memory: SliceRawParts(
                                                    memory.data_ptr(&caller),
                                                    memory.data_size(&caller),
                                                ),
                                                expected_return_ty,
                                            };
                                            task::Poll::Pending
                                        }
                                        Shared::Return {
                                            ref mut return_value,
                                            memory,
                                        } => {
                                            if let Some(returned) = return_value.take() {
                                                assert_eq!(ret_val.len(), 1);
                                                ret_val[0] = From::from(returned);
                                            } else {
                                                assert!(ret_val.is_empty());
                                            }

                                            *shared_lock = Shared::OutsideFunctionCall { memory };
                                            task::Poll::Ready(Ok(()))
                                        }
                                        _ => unreachable!(),
                                    }
                                }))
                            },
                        )));
                    }
                    wasmtime::ExternType::Global(_) | wasmtime::ExternType::Table(_) => {
                        unreachable!() // Should have been checked earlier.
                    }
                    wasmtime::ExternType::Memory(m) => {
                        if module_import.module() != "env" || module_import.name() != "memory" {
                            return Err(NewErr::MemoryNotNamedMemory);
                        }

                        // Considering that the memory can only be "env":"memory", and that each
                        // import has a unique name, this block can't be reached more than once.
                        debug_assert!(imported_memory.is_none());
                        imported_memory = Some(
                            wasmtime::Memory::new(&mut store, m)
                                .map_err(|_| NewErr::CouldntAllocateMemory)?,
                        );
                        imports.push(wasmtime::Extern::Memory(*imported_memory.as_ref().unwrap()));
                    }
                };
            }
            imports
        };

        // Calling `wasmtime::Instance::new` executes the `start` function of the module, if any.
        // If this `start` function calls into one of the imports, then the import will detect
        // that the shared state is `ExecutingStart` and return an error.
        // This function call is asynchronous because the `start` function might be asynchronous.
        // In principle, `now_or_never()` can be unwrapped because the only way for `start` to
        // not be immediately finished is if it enters an import, which immediately returns an
        // error. However we return an error anyway, just in case.
        // If the `start` function doesn't call any import, then it will go undetected and no
        // error will be returned.
        // TODO: detect `start` anyway, for consistency with other backends
        let instance = match future::Future::poll(
            pin::pin!(wasmtime::Instance::new_async(
                &mut store,
                &base_components.module,
                &imports
            )),
            &mut task::Context::from_waker(&noop_waker()),
        ) {
            task::Poll::Pending => return Err(NewErr::StartFunctionNotSupported), // TODO: hacky error value, as the error could also be different
            task::Poll::Ready(Ok(i)) => i,
            task::Poll::Ready(Err(err)) => return Err(NewErr::Instantiation(err.to_string())),
        };

        // Now that we are passed the `start` stage, update the state of execution.
        *shared.lock().unwrap() = Shared::Poisoned;

        let exported_memory = if let Some(mem) = instance.get_export(&mut store, "memory") {
            if let Some(mem) = mem.into_memory() {
                Some(mem)
            } else {
                return Err(NewErr::MemoryIsntMemory);
            }
        } else {
            None
        };

        let memory = match (exported_memory, imported_memory) {
            (Some(_), Some(_)) => return Err(NewErr::TwoMemories),
            (Some(m), None) => m,
            (None, Some(m)) => m,
            (None, None) => return Err(NewErr::NoMemory),
        };

        let memory_type = memory.ty(&store);

        Ok(JitPrototype {
            base_components,
            store,
            instance,
            shared,
            memory,
            memory_type,
        })
    }

    /// See [`super::VirtualMachinePrototype::global_value`].
    pub fn global_value(&mut self, name: &str) -> Result<u32, GlobalValueErr> {
        match self.instance.get_export(&mut self.store, name) {
            Some(wasmtime::Extern::Global(g)) => match g.get(&mut self.store) {
                wasmtime::Val::I32(v) => Ok(u32::from_ne_bytes(v.to_ne_bytes())),
                _ => Err(GlobalValueErr::Invalid),
            },
            _ => Err(GlobalValueErr::NotFound),
        }
    }

    /// See [`super::VirtualMachinePrototype::memory_max_pages`].
    pub fn memory_max_pages(&self) -> Option<HeapPages> {
        let num = self.memory.ty(&self.store).maximum()?;
        match u32::try_from(num) {
            Ok(n) => Some(HeapPages::new(n)),
            // If `num` doesn't fit in a `u32`, we return `None` to mean "infinite".
            Err(_) => None,
        }
    }

    /// See [`super::VirtualMachinePrototype::prepare`].
    pub fn prepare(self) -> Prepare {
        Prepare { inner: self }
    }
}

impl Clone for JitPrototype {
    fn clone(&self) -> Self {
        // `from_base_components` is deterministic: either it errors all the time or it never
        // errors. Since we've called it before and it didn't error, we know that it will also
        // not error.
        // The only exception is `NewErr::CouldntAllocateMemory`, but lack of memory is always an
        // acceptable reason to panic.
        JitPrototype::from_base_components(BaseComponents {
            module: self.base_components.module.clone(),
            resolved_imports: self.base_components.resolved_imports.clone(),
        })
        .unwrap()
    }
}

impl fmt::Debug for JitPrototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("JitPrototype").finish()
    }
}

/// See [`super::Prepare`].
pub struct Prepare {
    inner: JitPrototype,
}

impl Prepare {
    /// See [`super::Prepare::into_prototype`].
    pub fn into_prototype(self) -> JitPrototype {
        // Since the creation has succeeded before, there's no reason why it would fail now.
        JitPrototype::from_base_components(self.inner.base_components).unwrap()
    }

    /// See [`super::Prepare::memory_size`].
    pub fn memory_size(&self) -> HeapPages {
        let heap_pages = self.inner.memory.size(&self.inner.store);
        HeapPages::new(u32::try_from(heap_pages).unwrap())
    }

    /// See [`super::Prepare::read_memory`].
    pub fn read_memory(
        &'_ self,
        offset: u32,
        size: u32,
    ) -> Result<impl AsRef<[u8]> + '_, OutOfBoundsError> {
        let memory_slice = self.inner.memory.data(&self.inner.store);

        let start = usize::try_from(offset).map_err(|_| OutOfBoundsError)?;
        let end = start
            .checked_add(usize::try_from(size).map_err(|_| OutOfBoundsError)?)
            .ok_or(OutOfBoundsError)?;

        if end > memory_slice.len() {
            return Err(OutOfBoundsError);
        }

        Ok(&memory_slice[start..end])
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

    /// See [`super::Prepare::grow_memory`].
    pub fn grow_memory(&mut self, additional: HeapPages) -> Result<(), OutOfBoundsError> {
        let additional = u64::from(u32::from(additional));
        self.inner
            .memory
            .grow(&mut self.inner.store, additional)
            .map_err(|_| OutOfBoundsError)?;
        Ok(())
    }

    /// See [`super::Prepare::start`].
    pub fn start(
        mut self,
        function_name: &str,
        params: &[WasmValue],
    ) -> Result<Jit, (StartErr, JitPrototype)> {
        let function_to_call = match self
            .inner
            .instance
            .get_export(&mut self.inner.store, function_name)
        {
            Some(export) => match export.into_func() {
                Some(f) => f,
                None => return Err((StartErr::NotAFunction, self.inner)),
            },
            None => return Err((StartErr::FunctionNotFound, self.inner)),
        };

        // Try to convert the signature of the function to call, in order to make sure
        // that the type of parameters and return value are supported.
        let Ok(signature) = Signature::try_from(&function_to_call.ty(&self.inner.store)) else {
            return Err((StartErr::SignatureNotSupported, self.inner));
        };

        // Check the types of the provided parameters.
        if params.len() != signature.parameters().len() {
            return Err((StartErr::InvalidParameters, self.inner));
        }
        for (obtained, expected) in params.iter().zip(signature.parameters()) {
            if obtained.ty() != *expected {
                return Err((StartErr::InvalidParameters, self.inner));
            }
        }

        // This function only performs all the verifications and preparations, but the call isn't
        // actually started here because we might still need to potentially access `store`
        // before being in the context of a function handler.

        Ok(Jit {
            base_components: self.inner.base_components,
            inner: JitInner::NotStarted {
                store: self.inner.store,
                function_to_call,
                params: params.iter().map(|v| (*v).into()).collect::<Vec<_>>(),
            },
            shared: self.inner.shared,
            memory: self.inner.memory,
            memory_type: self.inner.memory_type,
        })
    }
}

impl fmt::Debug for Prepare {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Prepare").finish()
    }
}

/// Data shared between the external API and the functions that `wasmtime` directly invokes.
///
/// The flow is as follows:
///
/// - `wasmtime` calls a function that shares access to a `Arc<Mutex<Shared>>`. The `Shared` is in
/// the [`Shared::OutsideFunctionCall`] state.
/// - This function switches the state to the [`Shared::EnteredFunctionCall`] state and returns
/// `Poll::Pending`.
/// - This `Pending` gets propagated to the body of [`Jit::run`], which was calling `wasmtime`.
/// [`Jit::run`] reads `function_index` and `parameters` to determine what happened, switches the
/// state of the `Shared` to [`Shared::WithinFunctionCall`] state, and returns `Poll::Pending`.
/// - Here, the user can access the memory, in which case the `Shared` is read. If the user wants
/// to grow the memory, the state is switched to [`Shared::MemoryGrowRequired`], then execution
/// resumed for the function to perform the growth and transition back to
/// [`Shared::WithinFunctionCall`].
/// - Later, the state is switched to [`Shared::Return`], and execution is resumed.
/// - The function called by `wasmtime` reads the return value and returns `Poll::Ready`.
///
enum Shared {
    Poisoned,
    ExecutingStart,
    OutsideFunctionCall {
        memory: wasmtime::Memory,
    },
    /// Function handler switches to this state as soon as it is entered, so that the host can
    /// pick up this state, extract the function index and parameters, and transition to
    /// [`Shared::WithinFunctionCall`].
    EnteredFunctionCall {
        /// Index of the function currently being called.
        function_index: usize,
        /// Parameters of the function currently being called.
        parameters: Vec<WasmValue>,

        /// See [`Shared::WithinFunctionCall::memory`].
        memory: SliceRawParts,
        /// See [`Shared::WithinFunctionCall::expected_return_ty`].
        expected_return_ty: Option<ValueType>,
        /// See [`Shared::WithinFunctionCall::in_interrupted_waker`].
        in_interrupted_waker: Option<task::Waker>,
    },
    WithinFunctionCall {
        /// Pointer and size of the location where the virtual machine memory is located in the
        /// host memory. This pointer is invalidated if the memory is grown, which can happen
        /// between function calls.
        memory: SliceRawParts,

        /// Type of the return value of the function.
        expected_return_ty: Option<ValueType>,

        /// `Waker` that `wasmtime` has passed to the future that is waiting for `return_value`.
        /// This value is most likely not very useful, because [`Jit::run`] always polls the outer
        /// future whenever the inner future is known to be ready.
        /// However, it would be completely legal for `wasmtime` to not poll the inner future if the
        /// `waker` that it has passed (the one stored here) wasn't waken up.
        /// This field therefore exists in order to future-proof against this possible optimization
        /// that `wasmtime` might perform in the future.
        in_interrupted_waker: Option<task::Waker>,
    },
    MemoryGrowRequired {
        memory: wasmtime::Memory,
        additional: u64,
    },
    Return {
        /// Value to return to the Wasm code.
        return_value: Option<WasmValue>,
        memory: wasmtime::Memory,
    },
}

/// This idiotic struct and unsafe code are necessary because Rust doesn't implement `Send` and
/// `Sync` for raw pointers.
#[derive(Copy, Clone)]
struct SliceRawParts(*mut u8, usize);
unsafe impl Send for SliceRawParts {}
unsafe impl Sync for SliceRawParts {}

/// See [`super::VirtualMachine`].
pub struct Jit {
    /// Base components that can be used to recreate a prototype later if desired.
    base_components: BaseComponents,

    inner: JitInner,

    /// Shared between the "outside" and the external functions. See [`Shared`].
    shared: Arc<Mutex<Shared>>,

    /// See [`JitPrototype::memory`].
    memory: wasmtime::Memory,

    /// See [`JitPrototype::memory_type`].
    memory_type: wasmtime::MemoryType,
}

enum JitInner {
    Poisoned,

    /// Execution has not started yet.
    NotStarted {
        store: wasmtime::Store<()>,
        function_to_call: wasmtime::Func,
        params: Vec<wasmtime::Val>,
    },
    /// `Future` that drives the execution. Contains an invocation of `wasmtime::Func::call_async`.
    Executing(BoxFuture<(wasmtime::Store<()>, ExecOutcomeValue)>),
    /// Execution has finished because the future has returned `Poll::Ready` in the past.
    Done(wasmtime::Store<()>),
}

type BoxFuture<T> = pin::Pin<Box<dyn future::Future<Output = T> + Send>>;
type ExecOutcomeValue = Result<Option<WasmValue>, wasmtime::Error>;

impl Jit {
    /// See [`super::VirtualMachine::run`].
    pub fn run(&mut self, value: Option<WasmValue>) -> Result<ExecOutcome, RunErr> {
        // Make sure that `self.inner` is in `JitInner::Executing` start, starting the call if
        // necessary.
        match self.inner {
            JitInner::Executing(_) => {
                // Virtual machine was already executing. Update `Shared` to store the return
                // value, so that the function handler picks it up and returns it to `wasmtime`.
                let mut shared_lock = self.shared.try_lock().unwrap();
                match mem::replace(&mut *shared_lock, Shared::Poisoned) {
                    Shared::WithinFunctionCall {
                        in_interrupted_waker,
                        expected_return_ty,
                        memory,
                    } => {
                        let provided_value_ty = value.as_ref().map(|v| v.ty());
                        if expected_return_ty != provided_value_ty {
                            *shared_lock = Shared::WithinFunctionCall {
                                in_interrupted_waker,
                                expected_return_ty,
                                memory,
                            };
                            return Err(RunErr::BadValueTy {
                                expected: expected_return_ty,
                                obtained: provided_value_ty,
                            });
                        }

                        *shared_lock = Shared::Return {
                            return_value: value,
                            memory: self.memory,
                        };

                        if let Some(waker) = in_interrupted_waker {
                            waker.wake();
                        }
                    }
                    _ => unreachable!(),
                }
            }
            JitInner::Done(_) => return Err(RunErr::Poisoned),
            JitInner::Poisoned => unreachable!(),
            JitInner::NotStarted { .. } => {
                if value.is_some() {
                    return Err(RunErr::BadValueTy {
                        expected: None,
                        obtained: value.as_ref().map(|v| v.ty()),
                    });
                }

                let (function_to_call, params, mut store) =
                    match mem::replace(&mut self.inner, JitInner::Poisoned) {
                        JitInner::NotStarted {
                            function_to_call,
                            params,
                            store,
                        } => (function_to_call, params, store),
                        _ => unreachable!(),
                    };

                *self.shared.try_lock().unwrap() = Shared::OutsideFunctionCall {
                    memory: self.memory,
                };

                // Check whether the function to call has a return value.
                // We made sure when starting that the signature was supported.
                let has_return_value = Signature::try_from(&function_to_call.ty(&store))
                    .unwrap()
                    .return_type()
                    .is_some();

                // Starting the function call.
                let function_call = Box::pin(async move {
                    // Prepare an array of results to pass to `wasmtime`. Note that the type doesn't
                    // have to match the actual return value, only the length.
                    let mut result = [wasmtime::Val::I32(0)];

                    let outcome = function_to_call
                        .call_async(
                            &mut store,
                            &params,
                            &mut result[..(if has_return_value { 1 } else { 0 })],
                        )
                        .await;

                    // Execution resumes here when the Wasm code has finished, gracefully or not.
                    match outcome {
                        Ok(()) if has_return_value => {
                            // TODO: could implement TryFrom on wasmtime::Val instead of &wasmtime::Val to avoid borrow here?
                            (store, Ok(Some((&result[0]).try_into().unwrap())))
                        }
                        Ok(()) => (store, Ok(None)),
                        Err(err) => (store, Err(err)),
                    }
                });

                self.inner = JitInner::Executing(function_call);
            }
        };

        // We made sure that the state is in `Executing`. Now grab the future.
        let function_call = match &mut self.inner {
            JitInner::Executing(f) => f,
            _ => unreachable!(),
        };

        // Resume the coroutine execution.
        // The `Future` is polled with a no-op waker. We are in total control of when the
        // execution might be able to progress, hence the lack of need for a waker.
        match future::Future::poll(
            function_call.as_mut(),
            &mut task::Context::from_waker(&noop_waker()),
        ) {
            task::Poll::Ready((store, Ok(val))) => {
                self.inner = JitInner::Done(store);
                Ok(ExecOutcome::Finished {
                    // Since we verify at initialization that the signature of the function to
                    // call is supported, it is guaranteed that the type of this return value is
                    // supported too.
                    return_value: Ok(val),
                })
            }
            task::Poll::Ready((store, Err(err))) => {
                self.inner = JitInner::Done(store);
                Ok(ExecOutcome::Finished {
                    return_value: Err(Trap(err.to_string())),
                })
            }
            task::Poll::Pending => {
                let mut shared_lock = self.shared.try_lock().unwrap();
                match mem::replace(&mut *shared_lock, Shared::Poisoned) {
                    Shared::EnteredFunctionCall {
                        function_index,
                        parameters,
                        memory,
                        expected_return_ty,
                        in_interrupted_waker,
                    } => {
                        *shared_lock = Shared::WithinFunctionCall {
                            memory,
                            expected_return_ty,
                            in_interrupted_waker,
                        };

                        Ok(ExecOutcome::Interrupted {
                            id: function_index,
                            params: parameters,
                        })
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    /// See [`super::VirtualMachine::memory_size`].
    pub fn memory_size(&self) -> HeapPages {
        match &self.inner {
            JitInner::NotStarted { store, .. } | JitInner::Done(store) => {
                let heap_pages = self.memory.size(store);
                HeapPages::new(u32::try_from(heap_pages).unwrap())
            }
            JitInner::Executing(_) => {
                let size_bytes = match *self.shared.try_lock().unwrap() {
                    Shared::WithinFunctionCall { memory, .. } => memory.1,
                    _ => unreachable!(),
                };

                if size_bytes == 0 {
                    HeapPages::new(0)
                } else {
                    HeapPages::new(1 + u32::try_from((size_bytes - 1) / (64 * 1024)).unwrap())
                }
            }
            JitInner::Poisoned => unreachable!(),
        }
    }

    /// See [`super::VirtualMachine::read_memory`].
    pub fn read_memory(
        &'_ self,
        offset: u32,
        size: u32,
    ) -> Result<impl AsRef<[u8]> + '_, OutOfBoundsError> {
        let memory_slice = match &self.inner {
            JitInner::NotStarted { store, .. } | JitInner::Done(store) => self.memory.data(store),
            JitInner::Executing(_) => {
                let memory = match *self.shared.try_lock().unwrap() {
                    Shared::WithinFunctionCall { memory, .. } => memory,
                    _ => unreachable!(),
                };

                unsafe { slice::from_raw_parts(memory.0, memory.1) }
            }
            JitInner::Poisoned => unreachable!(),
        };

        let start = usize::try_from(offset).map_err(|_| OutOfBoundsError)?;
        let end = start
            .checked_add(usize::try_from(size).map_err(|_| OutOfBoundsError)?)
            .ok_or(OutOfBoundsError)?;

        if end > memory_slice.len() {
            return Err(OutOfBoundsError);
        }

        Ok(&memory_slice[start..end])
    }

    /// See [`super::VirtualMachine::write_memory`].
    pub fn write_memory(&mut self, offset: u32, value: &[u8]) -> Result<(), OutOfBoundsError> {
        let memory_slice = match &mut self.inner {
            JitInner::NotStarted { store, .. } | JitInner::Done(store) => {
                self.memory.data_mut(store)
            }
            JitInner::Executing(_) => {
                let memory = match *self.shared.try_lock().unwrap() {
                    Shared::WithinFunctionCall { memory, .. } => memory,
                    _ => unreachable!(),
                };

                unsafe { slice::from_raw_parts_mut(memory.0, memory.1) }
            }
            JitInner::Poisoned => unreachable!(),
        };

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

    /// See [`super::VirtualMachine::grow_memory`].
    pub fn grow_memory(&mut self, additional: HeapPages) -> Result<(), OutOfBoundsError> {
        let additional = u64::from(u32::from(additional));

        match &mut self.inner {
            JitInner::NotStarted { store, .. } | JitInner::Done(store) => {
                // This is the simple case: we still have access to the `store` and can perform
                // the growth synchronously.
                self.memory
                    .grow(store, additional)
                    .map_err(|_| OutOfBoundsError)?;
            }
            JitInner::Poisoned => unreachable!(),
            JitInner::Executing(function_call) => {
                // This is the complicated case: the call is in progress and we don't have access
                // to the `store`. Switch `Shared` to `MemoryGrowRequired`, then resume execution
                // so that the function handler performs the grow.
                let mut shared_lock = self.shared.try_lock().unwrap();
                match mem::replace(&mut *shared_lock, Shared::Poisoned) {
                    Shared::WithinFunctionCall {
                        memory,
                        expected_return_ty,
                        in_interrupted_waker,
                    } => {
                        // We check now what the memory bounds are, as it is more difficult to
                        // recover from `grow` returning an error than checking manually.
                        let current_pages = if memory.1 == 0 {
                            0
                        } else {
                            1 + u64::try_from((memory.1 - 1) / (64 * 1024)).unwrap()
                        };
                        if self
                            .memory_type
                            .maximum()
                            .map_or(false, |max| current_pages + additional > max)
                        {
                            // Put everything back as it was.
                            *shared_lock = Shared::WithinFunctionCall {
                                memory,
                                expected_return_ty,
                                in_interrupted_waker,
                            };
                            return Err(OutOfBoundsError);
                        }

                        if let Some(waker) = in_interrupted_waker {
                            waker.wake();
                        }

                        *shared_lock = Shared::MemoryGrowRequired {
                            memory: self.memory,
                            additional,
                        }
                    }
                    _ => unreachable!(),
                }
                drop(shared_lock);

                // Resume the coroutine execution once for the function handler to pick up the
                // `MemoryGrowRequired`, perform the grow, and switch back to `WithinFunctionCall`.
                // The `Future` is polled with a no-op waker. We are in total control of when the
                // execution might be able to progress, hence the lack of need for a waker.
                match future::Future::poll(
                    function_call.as_mut(),
                    &mut task::Context::from_waker(&noop_waker()),
                ) {
                    task::Poll::Ready(_) => unreachable!(),
                    task::Poll::Pending => {
                        debug_assert!(matches!(
                            *self.shared.try_lock().unwrap(),
                            Shared::WithinFunctionCall { .. }
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// See [`super::VirtualMachine::into_prototype`].
    pub fn into_prototype(self) -> JitPrototype {
        // Since the creation has succeeded before, there's no reason why it would fail now.
        JitPrototype::from_base_components(self.base_components).unwrap()
    }
}

impl fmt::Debug for Jit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Jit").finish()
    }
}

fn noop_waker() -> task::Waker {
    // Safety: all the requirements in the documentation of wakers (e.g. thread safety) is
    // irrelevant here due to the implementation being trivial.
    unsafe {
        fn clone(_: *const ()) -> task::RawWaker {
            task::RawWaker::new(ptr::null(), &VTABLE)
        }
        fn noop(_: *const ()) {}
        static VTABLE: task::RawWakerVTable = task::RawWakerVTable::new(clone, noop, noop, noop);
        task::Waker::from_raw(task::RawWaker::new(ptr::null(), &VTABLE))
    }
}
