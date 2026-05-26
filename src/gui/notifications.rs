/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#[cfg(feature = "gui-notifications")]
use crate::error::Result;
#[cfg(feature = "gui-notifications")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "gui-notifications")]
use std::time::{Duration, Instant};

#[cfg(feature = "gui-notifications")]
pub trait NotificationSink: Send + Sync {
    fn notify(&self, title: &str, body: &str) -> Result<()>;
}

#[cfg(feature = "gui-notifications")]
pub struct DesktopNotificationSink;

#[cfg(feature = "gui-notifications")]
impl NotificationSink for DesktopNotificationSink {
    fn notify(&self, title: &str, body: &str) -> Result<()> {
        use notify_rust::Notification;
        Notification::new()
            .summary(title)
            .body(body)
            .appname("nkCryptoTool")
            .timeout(5000)
            .show()
            .map_err(|e| crate::error::CryptoError::Parameter(format!("Notification failed: {}", e)))?;
        Ok(())
    }
}

#[cfg(feature = "gui-notifications")]
pub struct NotificationManager {
    sink: Arc<dyn NotificationSink>,
    last_notification: Mutex<Option<Instant>>,
    rate_limit: Duration,
}

#[cfg(feature = "gui-notifications")]
impl NotificationManager {
    pub fn new(sink: Arc<dyn NotificationSink>) -> Self {
        Self {
            sink,
            last_notification: Mutex::new(None),
            rate_limit: Duration::from_secs(5),
        }
    }

    /// Leading-edge rate limited notification
    pub fn notify_message(&self, peer_id: &str, is_focused: bool) -> Result<()> {
        if is_focused {
            return Ok(());
        }

        let now = Instant::now();
        let mut last_notif = self.last_notification.lock().unwrap();
        
        if let Some(last) = *last_notif {
            if now.duration_since(last) < self.rate_limit {
                return Ok(()); // Suppress (Rate limited)
            }
        }

        *last_notif = Some(now);
        // Policy (a): Always generic message. peer_id is typically the first 8 chars of fingerprint.
        let body = format!("{} から新しいメッセージがあります", peer_id);
        self.sink.notify("nkCryptoTool: New Message", &body)
    }
}

#[cfg(any(test, feature = "testing"))]
pub struct MockNotificationSink {
    pub history: Mutex<Vec<(String, String)>>,
}

#[cfg(feature = "gui-notifications")]
#[cfg(any(test, feature = "testing"))]
impl NotificationSink for MockNotificationSink {
    fn notify(&self, title: &str, body: &str) -> Result<()> {
        self.history.lock().unwrap().push((title.to_string(), body.to_string()));
        Ok(())
    }
}
