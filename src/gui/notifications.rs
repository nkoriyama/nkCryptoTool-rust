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

    /// Escape the characters a markup-capable notification server interprets.
    ///
    /// The freedesktop spec lets a server advertise `body-markup`, and GNOME
    /// Shell, Plasma and dunst-with-markup then render a Pango subset —
    /// including `<a href="…">`, i.e. a clickable link inside a notification
    /// attributed to this application. Escaping is applied even though the only
    /// permitted label is an authenticated identity, because a notification is
    /// rendered outside the application window where the user has no way to
    /// judge its provenance.
    fn escape_markup(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '\'' => out.push_str("&apos;"),
                '"' => out.push_str("&quot;"),
                _ => out.push(c),
            }
        }
        out
    }

    /// Longest label rendered in a notification body. Chat messages may be up
    /// to 65000 bytes; a notification is not a place to reproduce that.
    const MAX_LABEL_CHARS: usize = 32;

    /// Leading-edge rate limited notification.
    ///
    /// `peer` must be an **authenticated** identity — the handshake fingerprint
    /// or a locally-configured name — never anything parsed out of the peer's
    /// own message. Pass `None` when no such identity is available; the body is
    /// then generic, which is the honest rendering. (It previously received a
    /// label parsed from `[name]` in the peer's message text, letting the peer
    /// choose what a notification bearing this application's name said.)
    pub fn notify_message(&self, peer: Option<&str>, is_focused: bool) -> Result<()> {
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
        // Policy (a): the body stays generic; a label is added only when an
        // authenticated identity was supplied, and then control-filtered,
        // markup-escaped and truncated.
        let body = match peer {
            Some(p) => {
                let label = Self::escape_markup(&crate::utils::sanitize_for_terminal_bounded(
                    p,
                    Self::MAX_LABEL_CHARS,
                ));
                format!("{} から新しいメッセージがあります", label)
            }
            None => "新しいメッセージがあります".to_string(),
        };
        self.sink.notify("nkCryptoTool: New Message", &body)
    }
}

#[cfg(all(test, feature = "gui-notifications"))]
mod tests {
    use super::*;

    fn manager() -> (NotificationManager, Arc<MockNotificationSink>) {
        let sink = Arc::new(MockNotificationSink {
            history: Mutex::new(Vec::new()),
        });
        (NotificationManager::new(sink.clone()), sink)
    }

    #[test]
    fn body_is_generic_when_no_authenticated_identity_is_supplied() {
        let (nm, sink) = manager();
        nm.notify_message(None, false).unwrap();
        let hist = sink.history.lock().unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].1, "新しいメッセージがあります");
    }

    #[test]
    fn a_label_cannot_carry_markup_or_a_link() {
        // The exact payload from the finding: an anchor tag that a markup
        // capable notification server would render as a clickable link
        // attributed to nkCryptoTool.
        let (nm, sink) = manager();
        nm.notify_message(
            Some("<a href=\"https://evil.example/reauth\">nkCryptoTool Security</a>"),
            false,
        )
        .unwrap();
        let hist = sink.history.lock().unwrap();
        let body = &hist[0].1;
        // The property is that no *markup* survives: the angle brackets are
        // entity-encoded, so a markup-capable server renders the payload as
        // literal text instead of an anchor. (`href=` may still appear as
        // plain text — inert once the brackets are gone.)
        assert!(!body.contains('<'), "raw '<' survived: {body}");
        assert!(!body.contains('>'), "raw '>' survived: {body}");
        assert!(body.contains("&lt;a"), "expected escaped markup: {body}");
    }

    #[test]
    fn a_label_is_truncated_and_control_filtered() {
        let (nm, sink) = manager();
        nm.notify_message(Some(&format!("{}\u{1b}[2K", "x".repeat(500))), false)
            .unwrap();
        let hist = sink.history.lock().unwrap();
        let body = &hist[0].1;
        assert!(!body.contains('\u{1b}'), "ESC survived: {body}");
        assert!(body.chars().count() < 100, "label was not truncated: {body}");
    }

    #[test]
    fn focused_window_suppresses_the_notification() {
        let (nm, sink) = manager();
        nm.notify_message(None, true).unwrap();
        assert!(sink.history.lock().unwrap().is_empty());
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
