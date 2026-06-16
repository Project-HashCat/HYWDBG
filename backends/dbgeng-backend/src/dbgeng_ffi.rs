//! DbgEng binding placeholder.
//!
//! Planned real path:
//! - CoInitializeEx
//! - DebugCreate(__uuidof(IDebugClient5), ...)
//! - QueryInterface IDebugControl / IDebugDataSpaces / IDebugRegisters / IDebugSymbols
//! - Install IDebugEventCallbacks
//! - AttachProcess or CreateProcessAndAttach
//! - WaitForEvent event pump

#[cfg(all(windows, feature = "real-dbgeng"))]
mod real {
    // Use `windows` crate or bindgen over dbgeng.h.
}
