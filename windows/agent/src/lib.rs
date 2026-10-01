//! PhoneGate Windows agent library. The binary (`main.rs`) wires the engine to the TPM, the
//! named pipes and the Windows service control manager.

pub mod api;
pub mod bitlocker_logic;
pub mod credcache;
pub mod engine;
pub mod keys;
pub mod probe;
pub mod watchdog;
pub mod state;

#[cfg(windows)]
pub mod win;
