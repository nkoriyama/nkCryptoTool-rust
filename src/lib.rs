/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

pub mod backend;
pub mod config;
pub mod error;
pub mod key;
pub mod network;
pub mod p2p;
pub mod processor;
#[cfg(any(feature = "mls", feature = "mls-redb"))]
pub mod group;
#[cfg(feature = "mls")]
pub mod prekey;
#[cfg(feature = "mobile-ffi")]
pub mod ffi;
// UniFFI scaffolding must live at the crate root so the generated `UniFfiTag`
// is visible to the `#[uniffi::export]` macros in `ffi`.
#[cfg(feature = "mobile-ffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "mls")]
pub mod one_shot;
pub mod gui;
#[cfg(feature = "gui-camera")]
pub mod camera { pub use crate::gui::camera::*; }
pub mod shell;
pub mod strategy;
pub mod ticket;
pub mod utils;

pub use error::CryptoError;
pub use processor::{CryptoProcessor, ProgressCallback};
