//! Query tables: `RtlQueryRegistryValues` and
//! `RtlQueryRegistryValuesEx`.
//!
//! `nk_cm::query` decides what a table asks for, one action at a time.
//! This file copies the caller's table, reads the registry for the
//! query, and does each action: calls the driver's routine, writes
//! through an entry's pointer, deletes a value.
//!
//! A routine may raise an exception that a handler beneath the caller
//! takes; the call into it is then unwound and never returns here. So
//! all that a query holds is in one pool block, a [`Run`], which the
//! guard of that call gives back (`doc/DESIGN.md`, "Exceptions"), and
//! the frames of this file hold nothing else across it.

use super::{HIVE, absolute, key_of, status};
use crate::ke::seh::{self, Guard};
use crate::mm::pool;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_cm::query::{self, Action, Entry, Query, QueryError, Reader, Table, Value};
use nk_cm::{Error, Hive, KeyId};
use nk_ntabi::cm::{
    REG_EXPAND_SZ, REG_MULTI_SZ, REG_NONE, REG_SZ, RTL_QUERY_REGISTRY_ROUTINE,
    RTL_QUERY_REGISTRY_TABLE, RTL_REGISTRY_ABSOLUTE, RTL_REGISTRY_CONTROL, RTL_REGISTRY_DEVICEMAP,
    RTL_REGISTRY_HANDLE, RTL_REGISTRY_OPTIONAL, RTL_REGISTRY_SERVICES, RTL_REGISTRY_USER,
    RTL_REGISTRY_WINDOWS_NT,
};
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::status::*;

/// The pool tag of a query's own blocks.
const TAG: u32 = u32::from_le_bytes(*b"CmQt");
/// The pool tag of a string buffer made for the caller, who frees it.
const TAG_STRING: u32 = u32::from_le_bytes(*b"CmQs");

/// The keys `RelativeTo` stands for.
const SERVICES: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
const CONTROL: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\";
const WINDOWS_NT: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\";
const DEVICEMAP: &str = "\\Registry\\Machine\\Hardware\\DeviceMap\\";
/// The current user's key: the system's own, there being no other
/// user.
const USER: &str = "\\Registry\\User\\.Default\\";

/// One entry of the caller's table, copied.
struct Row {
    /// `QueryRoutine`, or zero.
    routine: usize,
    flags: u32,
    name: Option<Vec<u16>>,
    /// `EntryContext`.
    context: usize,
    default_type: u32,
    default_data: Vec<u8>,
}

/// The caller's table, copied up to the entry that ends it.
struct Rows(Vec<Row>);

impl Table for Rows {
    fn entry(&self, index: usize) -> Option<Entry<'_>> {
        self.0.get(index).map(|row| Entry {
            routine: row.routine != 0,
            flags: row.flags,
            name: row.name.as_deref(),
            default_type: row.default_type,
            default_data: &row.default_data,
        })
    }
}

/// How many units the string at `text` has before its terminator.
///
/// # Safety
/// `text` points to 16-bit units that end with a zero.
unsafe fn wide_len(text: *const u16) -> usize {
    let mut len = 0;
    // SAFETY: per the contract, every unit up to the zero is readable.
    while unsafe { text.add(len).read_unaligned() } != 0 {
        len += 1;
    }
    len
}

/// How many units the strings at `text` have, one after another, up to
/// and with the empty string that ends them.
///
/// # Safety
/// `text` points to terminated strings, the last of them empty.
unsafe fn wide_list_len(text: *const u16) -> usize {
    let mut at = 0;
    loop {
        // SAFETY: per the contract, another string starts here.
        let len = unsafe { wide_len(text.add(at)) };
        at += len + 1;
        if len == 0 {
            return at;
        }
    }
}

/// A copy of `len` units at `text`; `None` without memory for it.
///
/// # Safety
/// `text` is readable for `len` units.
unsafe fn units(text: *const u16, len: usize) -> Option<Vec<u16>> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(len).ok()?;
    // SAFETY: per the contract.
    copy.extend((0..len).map(|i| unsafe { text.add(i).read_unaligned() }));
    Some(copy)
}

/// The default data of an entry whose default has the type `kind`. A
/// string's length may be left for the kernel to measure, as Microsoft
/// documents; the data are copied now, not when a value turns out to
/// be missing. `None` without memory.
///
/// # Safety
/// `data` is null or readable for `length` bytes, or, where `length`
/// is zero and `kind` a string's, a string of that kind.
unsafe fn default_data(kind: u32, data: *const u8, length: u32) -> Option<Vec<u8>> {
    if data.is_null() || kind == REG_NONE {
        return Some(Vec::new());
    }
    // SAFETY: per the contract.
    unsafe {
        let length = match (length, kind) {
            (0, REG_SZ | REG_EXPAND_SZ) => 2 * (wide_len(data.cast()) + 1),
            (0, REG_MULTI_SZ) => 2 * wide_list_len(data.cast()),
            (length, _) => length as usize,
        };
        crate::se::copied(data, length)
    }
}

/// The caller's table, up to the entry that ends it. `None` without
/// memory.
///
/// # Safety
/// `table` points to entries, the last with neither routine nor name;
/// each name is a terminated string and each default what
/// [`default_data`] takes.
unsafe fn rows(table: *const RTL_QUERY_REGISTRY_TABLE) -> Option<Vec<Row>> {
    let mut rows = Vec::new();
    for index in 0.. {
        // SAFETY: per the contract, no entry before this one ended the
        // table. The table is the driver's, read field by field.
        let (routine, flags, name, context, default_type, data, length) = unsafe {
            let entry = table.add(index);
            (
                (&raw const (*entry).QueryRoutine)
                    .cast::<usize>()
                    .read_unaligned(),
                (&raw const (*entry).Flags).read_unaligned(),
                (&raw const (*entry).Name).read_unaligned(),
                (&raw const (*entry).EntryContext).read_unaligned(),
                (&raw const (*entry).DefaultType).read_unaligned(),
                (&raw const (*entry).DefaultData).read_unaligned(),
                (&raw const (*entry).DefaultLength).read_unaligned(),
            )
        };
        if routine == 0 && name.is_null() {
            break;
        }
        // SAFETY: per the contract.
        let (name, default_data) = unsafe {
            let name = if name.is_null() {
                None
            } else {
                Some(units(name, wide_len(name))?)
            };
            (
                name,
                default_data(default_type & 0xFF, data.cast(), length)?,
            )
        };
        rows.try_reserve(1).ok()?;
        rows.push(Row {
            routine,
            flags,
            name,
            context: context.addr(),
            default_type,
            default_data,
        });
    }
    Some(rows)
}

/// A copy of `items`.
fn copy<T: Copy>(items: &[T]) -> Result<Vec<T>, NTSTATUS> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(items.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    copy.extend_from_slice(items);
    Ok(copy)
}

/// The registry as a query reads it: the key the call names, and its
/// subkeys by path. Each read takes the registry's lock and hands back
/// copies, so that nothing is locked while a routine runs.
struct Registry(KeyId);

impl Registry {
    fn key(&self, hive: &Hive, subkey: Option<&[u16]>) -> Result<KeyId, Error> {
        hive.open(self.0, subkey.unwrap_or(&[]))
    }
}

impl Reader for Registry {
    fn has_key(&mut self, subkey: &[u16]) -> Result<bool, i32> {
        match self.key(&HIVE.lock(), Some(subkey)) {
            Ok(_) => Ok(true),
            Err(Error::NotFound) => Ok(false),
            Err(error) => Err(status(error)),
        }
    }

    fn value(&mut self, subkey: Option<&[u16]>, name: &[u16]) -> Result<Option<Value>, i32> {
        let hive = HIVE.lock();
        let key = self.key(&hive, subkey).map_err(status)?;
        match hive.value(key, name) {
            Ok((_, kind, data)) => Ok(Some((kind, copy(data)?))),
            Err(Error::NotFound) => Ok(None),
            Err(error) => Err(status(error)),
        }
    }

    fn value_at(
        &mut self,
        subkey: Option<&[u16]>,
        index: usize,
    ) -> Result<Option<(Vec<u16>, Value)>, i32> {
        let hive = HIVE.lock();
        let key = self.key(&hive, subkey).map_err(status)?;
        match hive.value_at(key, index).map_err(status)? {
            Some((name, kind, data)) => Ok(Some((copy(name)?, (kind, copy(data)?)))),
            None => Ok(None),
        }
    }
}

/// Everything a query holds while a routine of the driver's runs.
struct Run {
    /// The key the call names, counted as open: it stays the key it
    /// is, whatever the routine does to it.
    key: KeyId,
    rows: Rows,
    environment: Vec<u16>,
    query: Query,
    /// The block the routine being called was lent its value in.
    lent: *mut u8,
}

/// Give back what a query holds: at its end, or when the call into a
/// routine is unwound, as that call's guard.
///
/// # Safety
/// `run` is a `Run` in a pool block of its own, given back nowhere
/// else.
unsafe fn release(run: *mut c_void) {
    let run = run.cast::<Run>();
    // SAFETY: per the contract. What the run names is read before the
    // run is dropped; the blocks are the pool's, allocated by this
    // file.
    unsafe {
        let (key, lent) = ((*run).key, (*run).lent);
        run.drop_in_place();
        for block in [lent, run.cast()] {
            if !block.is_null()
                && let Err(error) = pool::free(block)
            {
                crate::kd::bugcheck(format_args!("a query table's block: {error:?}"));
            }
        }
        HIVE.lock().closed(key);
    }
}

/// A query routine's arguments.
struct RoutineCall {
    routine: usize,
    name: *mut u16,
    kind: u32,
    data: *mut c_void,
    length: u32,
    context: *mut c_void,
    entry_context: *mut c_void,
}

/// Call a query routine. It takes six arguments and the guarded call
/// passes four, so this is the function the guarded call calls: one
/// frame of NK's own between the guard and the routine, which holds
/// nothing and has an unwind entry like any other.
extern "C" fn pass_on(call: *const RoutineCall) -> NTSTATUS {
    // SAFETY: `work` passes a `RoutineCall` of its own, which names a
    // table entry's routine and what such a routine takes.
    unsafe {
        let call = call.read();
        let routine: RTL_QUERY_REGISTRY_ROUTINE = core::mem::transmute(call.routine);
        routine(
            call.name,
            call.kind,
            call.data,
            call.length,
            call.context,
            call.entry_context,
        )
    }
}

/// A pool block for a routine to be lent a value in: the data, two
/// zero bytes (a string stored without its terminator is terminated
/// all the same), then the name and its terminator. Returns the block,
/// which is where the data are, and where the name is. The routine is
/// given the kernel's copies, never the registry's own memory.
fn lend(name: &[u16], data: &[u8]) -> Option<(*mut u8, *mut u16)> {
    let name_at = (data.len() + 2).next_multiple_of(2);
    let size = name_at + 2 * (name.len() + 1);
    let block = pool::alloc_zeroed(size, TAG);
    if block.is_null() {
        return None;
    }
    // SAFETY: a fresh block of `size` bytes, which holds both copies;
    // pool blocks are aligned for 16-bit units.
    unsafe {
        block.copy_from_nonoverlapping(data.as_ptr(), data.len());
        let text = block.add(name_at).cast::<u16>();
        text.copy_from_nonoverlapping(name.as_ptr(), name.len());
        Some((block, text))
    }
}

/// Store a string in the counted string that is `slot` such structures
/// past `target`: in its buffer if it has one, which must have room
/// for the terminator too, or in a new one from the pool, which the
/// caller frees.
///
/// # Safety
/// `target` points to at least `slot + 1` counted strings, each
/// without a buffer or with one of its `MaximumLength` bytes.
unsafe fn store_string(target: usize, slot: usize, text: &[u8]) -> Result<(), NTSTATUS> {
    let chars = query::string_to_store(text);
    let room = chars.len() + 2;
    let string = core::ptr::without_provenance_mut::<UNICODE_STRING>(target).wrapping_add(slot);
    // SAFETY: per the contract. The structure and its buffer are the
    // driver's, read and written field by field and byte by byte.
    unsafe {
        let mut buffer = (&raw const (*string).Buffer).read_unaligned().cast::<u8>();
        if buffer.is_null() {
            // A counted string counts in 16 bits.
            let Ok(maximum) = u16::try_from(room) else {
                return Err(STATUS_BUFFER_TOO_SMALL);
            };
            buffer = pool::alloc(room, TAG_STRING);
            if buffer.is_null() {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            (&raw mut (*string).Buffer).write_unaligned(buffer.cast());
            (&raw mut (*string).MaximumLength).write_unaligned(maximum);
        } else if usize::from((&raw const (*string).MaximumLength).read_unaligned()) < room {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        for (i, &byte) in chars.iter().chain(&[0, 0]).enumerate() {
            buffer.add(i).write(byte);
        }
        (&raw mut (*string).Length).write_unaligned(chars.len() as u16);
    }
    Ok(())
}

/// Store data of more than four bytes in the buffer at `target`, whose
/// first 32 bits say how large it is and whether the data are to be
/// preceded by their length and type (`query::buffer_data_offset`).
///
/// # Safety
/// `target` points to a buffer of the size its first 32 bits give,
/// negated or not.
unsafe fn store_buffer(target: usize, kind: u32, data: &[u8]) -> Result<(), NTSTATUS> {
    let buffer = core::ptr::without_provenance_mut::<u8>(target);
    // SAFETY: per the contract; the data fit, by the check.
    unsafe {
        let declared = buffer.cast::<i32>().read_unaligned();
        let Some(offset) = query::buffer_data_offset(declared, data.len()) else {
            return Err(STATUS_BUFFER_TOO_SMALL);
        };
        if offset != 0 {
            buffer.cast::<u32>().write_unaligned(data.len() as u32);
            buffer.add(4).cast::<u32>().write_unaligned(kind);
        }
        for (i, &byte) in data.iter().enumerate() {
            buffer.add(offset + i).write(byte);
        }
    }
    Ok(())
}

/// What is left to do for an action once the query's own memory is no
/// longer needed for it.
enum Rest {
    /// Nothing: it was done, and went so.
    Done(Result<(), NTSTATUS>),
    /// Call the routine.
    Call(RoutineCall),
}

/// Do `action`, but for calling a routine, which is left to the
/// caller.
///
/// # Safety
/// `rows` is the caller's table, whose entries point where the
/// caller's table said: what an entry that stores directly points to
/// is what Microsoft documents for the value's type.
unsafe fn act(
    key: KeyId,
    rows: &Rows,
    lent: &mut *mut u8,
    context: *mut c_void,
    action: Action<'_>,
) -> Rest {
    let target = |entry: usize| rows.0[entry].context;
    // SAFETY: per the contract.
    Rest::Done(unsafe {
        match action {
            Action::Call {
                entry,
                name,
                kind,
                data,
            } => {
                let (routine, entry_context) = (rows.0[entry].routine, target(entry));
                // The call that carries no value carries no pointers.
                let (block, name) = match name.map(|name| lend(name, data)) {
                    Some(Some(lent)) => lent,
                    Some(None) => return Rest::Done(Err(STATUS_INSUFFICIENT_RESOURCES)),
                    None => (core::ptr::null_mut(), core::ptr::null_mut()),
                };
                *lent = block;
                return Rest::Call(RoutineCall {
                    routine,
                    name,
                    kind,
                    data: block.cast(),
                    length: data.len() as u32,
                    context,
                    entry_context: core::ptr::without_provenance_mut(entry_context),
                });
            }
            Action::StoreString { entry, slot, text } => store_string(target(entry), slot, text),
            Action::StoreSmall { entry, data } => {
                let to = core::ptr::without_provenance_mut::<u8>(target(entry));
                for (i, &byte) in data.iter().enumerate() {
                    to.add(i).write(byte);
                }
                Ok(())
            }
            Action::StoreBuffer { entry, kind, data } => store_buffer(target(entry), kind, data),
            Action::Delete { subkey, name } => {
                let mut hive = HIVE.lock();
                hive.open(key, subkey.unwrap_or(&[]))
                    .and_then(|key| hive.delete_value(key, name))
                    .map_err(status)
            }
        }
    })
}

/// Work through the table of `run`.
///
/// # Safety
/// `run` is a `Run` no one else has; its rows are a table as [`act`]
/// takes it, and their routines are routines that may be called now.
unsafe fn work(run: *mut Run, context: *mut c_void) -> NTSTATUS {
    let mut done = Ok(());
    loop {
        let rest = {
            // SAFETY: per the contract. The borrow ends with this
            // block, before any routine is called: a call that is
            // unwound gives the run back with nothing borrowed from it.
            let state = unsafe { &mut *run };
            let mut registry = Registry(state.key);
            let next = state
                .query
                .next(&state.rows, &state.environment, &mut registry, done);
            match next {
                // SAFETY: per the contract.
                Ok(Some(action)) => unsafe {
                    act(state.key, &state.rows, &mut state.lent, context, action)
                },
                Ok(None) => return STATUS_SUCCESS,
                Err(QueryError::InvalidParameter) => return STATUS_INVALID_PARAMETER,
                Err(QueryError::NotFound) => return STATUS_OBJECT_NAME_NOT_FOUND,
                Err(QueryError::TypeMismatch) => return STATUS_OBJECT_TYPE_MISMATCH,
                Err(QueryError::NoMemory) => return STATUS_INSUFFICIENT_RESOURCES,
                Err(QueryError::Failed(status)) => return status,
            }
        };
        done = match rest {
            Rest::Done(result) => result,
            Rest::Call(call) => {
                let guard = Guard::Undo {
                    undo: release,
                    context: run.cast(),
                };
                // SAFETY: per the contract, the routine may be called;
                // `pass_on` takes the one pointer. If the call is
                // unwound the guard releases the run, and this frame
                // and those above it in this file hold nothing else.
                let status = unsafe {
                    seh::call(
                        pass_on as *const () as usize,
                        [(&raw const call).addr(), 0, 0, 0],
                        &guard,
                    )
                } as NTSTATUS;
                // SAFETY: per the contract; the routine has returned,
                // and what it was lent is taken back.
                let lent = unsafe { core::mem::replace(&mut (*run).lent, core::ptr::null_mut()) };
                if !lent.is_null()
                    && let Err(error) = pool::free(lent)
                {
                    crate::kd::bugcheck(format_args!("a query routine's value: {error:?}"));
                }
                if nt_success(status) {
                    Ok(())
                } else {
                    Err(status)
                }
            }
        };
    }
}

/// The key a query is about, counted as open (`Hive::opened`).
///
/// # Safety
/// `path` is a key handle if `relative_to` says so, and else null or a
/// terminated string.
unsafe fn top_key(relative_to: u32, path: *const u16) -> Result<KeyId, NTSTATUS> {
    // A key that is called optional is opened like any other.
    let relative_to = relative_to & !RTL_REGISTRY_OPTIONAL;
    let (start, rest) = if relative_to & RTL_REGISTRY_HANDLE != 0 {
        (key_of(path.cast_mut().cast())?, Vec::new())
    } else {
        let prefix = match relative_to {
            RTL_REGISTRY_ABSOLUTE => "",
            RTL_REGISTRY_SERVICES => SERVICES,
            RTL_REGISTRY_CONTROL => CONTROL,
            RTL_REGISTRY_WINDOWS_NT => WINDOWS_NT,
            RTL_REGISTRY_DEVICEMAP => DEVICEMAP,
            RTL_REGISTRY_USER => USER,
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        let mut full: Vec<u16> = prefix.encode_utf16().collect();
        if !path.is_null() {
            // SAFETY: per the contract.
            let path = unsafe { units(path, wide_len(path)) };
            full.extend(path.ok_or(STATUS_INSUFFICIENT_RESOURCES)?);
        }
        absolute(&full)?
    };
    let mut hive = HIVE.lock();
    let key = hive.open(start, &rest).map_err(status)?;
    hive.opened(key);
    Ok(key)
}

/// Both exports.
///
/// # Safety
/// As [`RtlQueryRegistryValues`].
unsafe fn query_table(
    relative_to: u32,
    path: *const u16,
    table: *const RTL_QUERY_REGISTRY_TABLE,
    context: *mut c_void,
    environment: *const u16,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let key = match unsafe { top_key(relative_to, path) } {
        Ok(key) => key,
        Err(status) => return status,
    };
    // SAFETY: per the contract: the table, and an environment block,
    // which is strings ended by an empty one.
    let copied = unsafe {
        let environment = if environment.is_null() {
            Some(Vec::new())
        } else {
            units(environment, wide_list_len(environment))
        };
        (rows(table), environment)
    };
    let run = pool::alloc(size_of::<Run>(), TAG).cast::<Run>();
    let (Some(rows), Some(environment), false) = (copied.0, copied.1, run.is_null()) else {
        if !run.is_null() {
            let _ = pool::free(run.cast());
        }
        HIVE.lock().closed(key);
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: a fresh block of a `Run`'s size, aligned as the pool
    // aligns; from here on the run owns the copies and the key's
    // count, and `release` gives them back, here or as a guard.
    unsafe {
        run.write(Run {
            key,
            rows: Rows(rows),
            environment,
            query: Query::new(),
            lent: core::ptr::null_mut(),
        });
        let status = work(run, context);
        release(run.cast());
        status
    }
}

/// [`RtlQueryRegistryValues`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues):
/// read values of a key as a table of entries asks, handing each to
/// the entry's routine or storing it where the entry points.
///
/// - `RelativeTo` names the key the path starts at: the path itself,
///   the current control set's `Services` or `Control`, Windows NT's
///   `CurrentVersion`, the device map, the system's own user key; or
///   says the path is a key handle. `RTL_REGISTRY_OPTIONAL` changes
///   nothing: a key that is not there fails the call.
/// - A routine is called at the caller's IRQL with copies of the
///   value's name and data, which are the kernel's until it returns.
///   Nothing of the registry is locked meanwhile: the routine may read
///   and change the registry, this key included. An exception it
///   raises passes through to the caller's handlers, and the query
///   leaves nothing behind.
/// - A value stored directly need not be type-checked
///   (`RTL_QUERY_REGISTRY_TYPECHECK`): Windows demands the check for a
///   key in a hive it does not trust, and NK has no such hive.
///
/// # Safety
/// `path` is a terminated string, or a key handle if `relative_to`
/// says so; `table` points to entries, the last with neither routine
/// nor name, whose members are what Microsoft documents for their
/// flags; `environment` is null or strings ended by an empty one.
pub unsafe extern "C" fn RtlQueryRegistryValues(
    relative_to: u32,
    path: *const u16,
    table: *const RTL_QUERY_REGISTRY_TABLE,
    context: *mut c_void,
    environment: *const u16,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { query_table(relative_to, path, table, context, environment) }
}

/// [`RtlQueryRegistryValuesEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues):
/// [`RtlQueryRegistryValues`] under the name drivers built for Windows
/// 8 and later import. Windows tells the two apart only by how it
/// refuses an entry that stores directly, unchecked, from a hive it
/// does not trust; on NK no hive is such a hive.
///
/// # Safety
/// As [`RtlQueryRegistryValues`].
pub unsafe extern "C" fn RtlQueryRegistryValuesEx(
    relative_to: u32,
    path: *const u16,
    table: *const RTL_QUERY_REGISTRY_TABLE,
    context: *mut c_void,
    environment: *const u16,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { query_table(relative_to, path, table, context, environment) }
}
