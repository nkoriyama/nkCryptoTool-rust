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
        let requested = RequestedFormat::new::<RgbFormat>(RequestedFormatType::Absolute(
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

#[cfg(test)]
pub struct MockCameraSource {
    pub qr_data: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

#[cfg(feature = "gui-camera")]
#[cfg(test)]
impl CameraSource for MockCameraSource {
    fn start_scan(&self, callback: Arc<dyn Fn(Vec<u8>, u32, u32) + Send + Sync>) -> Result<()> {
        callback(self.qr_data.clone(), self.width, self.height);
        Ok(())
    }
    fn stop_scan(&self) -> Result<()> {
        Ok(())
    }
}
