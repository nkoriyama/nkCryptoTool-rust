/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#[cfg(feature = "gui-camera")]
use crate::error::{CryptoError, Result};
#[cfg(feature = "gui-camera")]
use nokhwa::{
    pixel_format::RgbFormat,
    utils::{CameraFormat, CameraIndex, RequestedFormat, RequestedFormatType},
    CallbackCamera,
};
#[cfg(feature = "gui-camera")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "gui-camera")]
pub trait CameraSource: Send + Sync {
    fn start_scan(&self, callback: Arc<dyn Fn(Vec<u8>, u32, u32) + Send + Sync>) -> Result<()>;
    fn stop_scan(&self) -> Result<()>;
}

#[cfg(feature = "gui-camera")]
pub struct NokhwaCameraSource {
    camera: Arc<Mutex<Option<CallbackCamera>>>,
}

#[cfg(feature = "gui-camera")]
impl NokhwaCameraSource {
    pub fn new() -> Self {
        Self {
            camera: Arc::new(Mutex::new(None)),
        }
    }
}

#[cfg(feature = "gui-camera")]
impl CameraSource for NokhwaCameraSource {
    fn start_scan(&self, callback: Arc<dyn Fn(Vec<u8>, u32, u32) + Send + Sync>) -> Result<()> {
        let index = CameraIndex::Index(0);
        let requested = RequestedFormat::new::<RgbFormat>(RequestedFormatType::Exact(
            CameraFormat::new_from(640, 480, nokhwa::utils::FrameFormat::YUYV, 30),
        ));
        
        let mut camera = CallbackCamera::new(index, requested, move |frame| {
            if let Ok(buffer) = frame.decode_image::<RgbFormat>() {
                callback(buffer.to_vec(), buffer.width(), buffer.height());
            }
        }).map_err(|e| CryptoError::Parameter(format!("Failed to open camera: {}", e)))?;
        
        camera.open_stream().map_err(|e| CryptoError::Parameter(format!("Failed to start stream: {}", e)))?;
        
        let mut cam_lock = self.camera.lock().unwrap();
        *cam_lock = Some(camera);
        
        Ok(())
    }

    fn stop_scan(&self) -> Result<()> {
        let mut cam_lock = self.camera.lock().unwrap();
        if let Some(mut cam) = cam_lock.take() {
            let _ = cam.stop_stream();
        }
        Ok(())
    }
}

/// Helper to decode QR from RGB frame
#[cfg(feature = "gui-camera")]
pub fn decode_qr_from_rgb(data: &[u8], width: u32, height: u32) -> Option<String> {
    use rqrr::PreparedImage;
    let mut img = PreparedImage::prepare_from_greyscale(width as usize, height as usize, |x, y| {
        let idx = ((y * width as usize + x) * 3) as usize;
        if idx + 2 < data.len() {
            // Simple grayscale conversion
            ((data[idx] as u32 + data[idx+1] as u32 + data[idx+2] as u32) / 3) as u8
        } else {
            0
        }
    });
    let grids = img.detect_grids();
    for grid in grids {
        if let Ok((_meta, content)) = grid.decode() {
            return Some(content);
        }
    }
    None
}

/// UX string mapping for camera errors
#[cfg(feature = "gui-camera")]
pub fn format_camera_error(e: &CryptoError) -> String {
    let err_str = e.to_string();
    if err_str.contains("Permission") || err_str.contains("Access denied") {
        "Camera permission denied. Check OS privacy settings.".to_string()
    } else if err_str.contains("not found") || err_str.contains("No such device") {
        "No camera detected. Please paste ticket manually.".to_string()
    } else {
        format!("Camera error: {}", e)
    }
}

/// UX string mapping for ticket parse errors
#[cfg(feature = "gui-camera")]
pub fn format_ticket_parse_error(e: &CryptoError) -> String {
    let err_str = e.to_string();
    if err_str.contains("Base32") {
        "Invalid ticket format (Base32 error).".to_string()
    } else if err_str.contains("Checksum") || err_str.contains("fingerprint") {
        "Invalid ticket checksum or fingerprint.".to_string()
    } else if err_str.contains("Version") {
        "Unsupported ticket version.".to_string()
    } else {
        "Scanned text is not a valid NKCT1 ticket. Continuing scan...".to_string()
    }
}

#[cfg(test)]
pub struct MockCameraSource {
    pub qr_data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub should_fail: bool,
}

#[cfg(test)]
impl CameraSource for MockCameraSource {
    fn start_scan(&self, callback: Arc<dyn Fn(Vec<u8>, u32, u32) + Send + Sync>) -> Result<()> {
        if self.should_fail {
            return Err(CryptoError::Parameter("No camera detected".to_string()));
        }
        callback(self.qr_data.clone(), self.width, self.height);
        Ok(())
    }
    fn stop_scan(&self) -> Result<()> {
        Ok(())
    }
}
