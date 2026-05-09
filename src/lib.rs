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
pub mod processor;

#[cfg(feature = "gui")]
pub mod gui;

#[cfg(feature = "gui-camera")]
pub mod camera { pub use crate::gui::camera::*; }
#[cfg(feature = "gui-notifications")]
pub mod notifications { pub use crate::gui::notifications::*; }
#[cfg(feature = "gui")]
pub mod file_picker { pub use crate::gui::file_picker::*; }

pub mod strategy;
pub mod ticket;
pub mod utils;

pub use error::CryptoError;
pub use processor::{CryptoProcessor, ProgressCallback};
