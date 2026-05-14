//! In-memory log ring buffer with tracing integration.
//!
//! Captures structured log events from the tracing subsystem and stores
//! the last N entries in a ring buffer. Provides both a REST endpoint
//! for historical queries and an SSE stream for live tailing.

use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use serde::Serialize;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tracing::Level;
use tracing_subscriber::Layer;

/// Global log buffer singleton.
static LOG_BUFFER: OnceLock<Arc<LogBuffer>> = OnceLock::new();

/// Get the global log buffer instance.
pub fn global_log_buffer() -> Arc<LogBuffer> {
    LOG_BUFFER.get_or_init(LogBuffer::new).clone()
}
/// Maximum number of log entries kept in the ring buffer.
const RING_BUFFER_CAPACITY: usize = 1000;

/// Broadcast channel capacity for SSE subscribers.
const BROADCAST_CAPACITY: usize = 256;

/// A single captured log entry.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// Timestamp in milliseconds since Unix epoch.
    pub ts: u64,
    /// Log level: "ERROR", "WARN", "INFO", "DEBUG", "TRACE".
    pub level: String,
    /// Log message.
    pub message: String,
    /// Target module path (tracing target).
    pub target: String,
}

/// Shared log ring buffer state.
#[derive(Debug)]
pub struct LogBuffer {
    /// Combined mutable state behind a single lock.
    state: parking_lot::Mutex<LogBufferState>,
    /// Broadcast sender for SSE subscribers.
    sender: broadcast::Sender<LogEntry>,
}

#[derive(Debug)]
struct LogBufferState {
    /// Ring buffer storing the most recent log entries.
    entries: Vec<LogEntry>,
    /// Write position in the ring buffer.
    write_pos: usize,
    /// Current number of entries (up to capacity).
    len: usize,
}

impl LogBuffer {
    /// Create a new log buffer with the default capacity.
    pub fn new() -> Arc<Self> {
        let (sender, _) = broadcast::channel(BROADCAST_CAPACITY);
        Arc::new(Self {
            state: parking_lot::Mutex::new(LogBufferState {
                entries: Vec::with_capacity(RING_BUFFER_CAPACITY),
                write_pos: 0,
                len: 0,
            }),
            sender,
        })
    }

    /// Push a new log entry into the ring buffer and broadcast it.
    pub fn push(&self, entry: LogEntry) {
        {
            let mut state = self.state.lock();
            if state.len < RING_BUFFER_CAPACITY {
                state.entries.push(entry.clone());
                state.write_pos = state.len;
                state.len += 1;
            } else {
                let pos = state.write_pos;
                let next_pos = (pos + 1) % RING_BUFFER_CAPACITY;
                state.entries[next_pos] = entry.clone();
                state.write_pos = next_pos;
            }
        }

        // Broadcast to SSE subscribers (ignore if no receivers).
        let _ = self.sender.send(entry);
    }

    /// Get the last `limit` entries, optionally filtered by minimum level.
    pub fn recent(
        &self,
        limit: usize,
        min_level: Option<&str>,
        search: Option<&str>,
    ) -> Vec<LogEntry> {
        let state = self.state.lock();
        let len = state.len;
        let write_pos = state.write_pos;
        let entries = &state.entries;

        let min_level_order = min_level.and_then(level_order);
        // Pre-compute the search needle once instead of per-entry.
        let search = search.map(|s| s.to_ascii_lowercase());

        let mut result = Vec::with_capacity(limit.min(len));
        // Iterate from newest to oldest.
        for i in 0..len {
            let idx = if len < RING_BUFFER_CAPACITY {
                // Buffer not full: entries at indices 0..len-1, newest is at len-1-i
                len - 1 - i
            } else {
                // Buffer full: write_pos points to newest entry
                (write_pos + RING_BUFFER_CAPACITY - i) % RING_BUFFER_CAPACITY
            };
            let entry = &entries[idx];
            if let Some(min_ord) = min_level_order
                && level_order(&entry.level).unwrap_or(0) > min_ord
            {
                continue;
            }
            if let Some(query) = &search {
                // Check each field individually to avoid format!() allocation per entry.
                let level = entry.level.to_ascii_lowercase();
                let target = entry.target.to_ascii_lowercase();
                let message = entry.message.to_ascii_lowercase();
                if !level.contains(query) && !target.contains(query) && !message.contains(query) {
                    continue;
                }
            }
            result.push(entry.clone());
            if result.len() >= limit {
                break;
            }
        }

        result
    }

    /// Subscribe to new log entries via broadcast receiver.
    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.sender.subscribe()
    }

    /// Current number of entries in the buffer.
    pub fn len(&self) -> usize {
        self.state.lock().len
    }

    /// Returns `true` if the buffer contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Convert level string to numeric order (lower = more severe).
fn level_order(level: &str) -> Option<usize> {
    match level {
        "ERROR" => Some(0),
        "WARN" => Some(1),
        "INFO" => Some(2),
        "DEBUG" => Some(3),
        "TRACE" => Some(4),
        _ => None,
    }
}

/// A tracing layer that captures log events into the shared ring buffer.
pub struct LogCaptureLayer {
    buffer: Arc<LogBuffer>,
}

impl LogCaptureLayer {
    pub fn new(buffer: Arc<LogBuffer>) -> Self {
        Self { buffer }
    }
}

impl<S> Layer<S> for LogCaptureLayer
where
    S: tracing::Subscriber + Send + Sync,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let metadata = event.metadata();
        let level = match *metadata.level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };

        // Collect all field values from the event into the message.
        let mut visitor = LogFieldVisitor::default();
        event.record(&mut visitor);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.buffer.push(LogEntry {
            ts,
            level: level.to_string(),
            message: visitor.message,
            target: metadata.target().to_string(),
        });
    }
}

/// Visitor that extracts the "message" field from a tracing event.
#[derive(Default)]
struct LogFieldVisitor {
    message: String,
}

impl tracing::field::Visit for LogFieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            // Append other fields as key=value.
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message
                .push_str(&format!("{}={}", field.name(), value));
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message
                .push_str(&format!("{}={:?}", field.name(), value));
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if !self.message.is_empty() {
            self.message.push(' ');
        }
        self.message
            .push_str(&format!("{}={}", field.name(), value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if !self.message.is_empty() {
            self.message.push(' ');
        }
        self.message
            .push_str(&format!("{}={}", field.name(), value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        if !self.message.is_empty() {
            self.message.push(' ');
        }
        self.message
            .push_str(&format!("{}={}", field.name(), value));
    }
}

/// Create an SSE stream from a broadcast receiver.
pub fn log_stream(
    buffer: Arc<LogBuffer>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let receiver = buffer.subscribe();
    let stream =
        tokio_stream::wrappers::BroadcastStream::new(receiver).filter_map(|result| match result {
            Ok(entry) => {
                let data = serde_json::to_string(&entry).unwrap_or_default();
                Some(Ok(Event::default().data(data)))
            }
            Err(_) => {
                // Skip lagged messages.
                None
            }
        });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_push_and_recent() {
        let buffer = LogBuffer::new();

        for i in 0..5 {
            buffer.push(LogEntry {
                ts: i as u64,
                level: "INFO".to_string(),
                message: format!("msg {}", i),
                target: "test".to_string(),
            });
        }

        assert_eq!(buffer.len(), 5);
        let recent = buffer.recent(3, None, None);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].message, "msg 4");
        assert_eq!(recent[2].message, "msg 2");
    }

    #[test]
    fn ring_buffer_wraps_around() {
        let buffer = LogBuffer::new();

        // Fill beyond capacity.
        for i in 0..(RING_BUFFER_CAPACITY + 10) {
            buffer.push(LogEntry {
                ts: i as u64,
                level: "INFO".to_string(),
                message: format!("msg {}", i),
                target: "test".to_string(),
            });
        }

        assert_eq!(buffer.len(), RING_BUFFER_CAPACITY);
        let recent = buffer.recent(1, None, None);
        // Should get the last pushed entry.
        assert_eq!(recent[0].ts, (RING_BUFFER_CAPACITY + 9) as u64);
    }

    #[test]
    fn ring_buffer_filters_by_level() {
        let buffer = LogBuffer::new();

        buffer.push(LogEntry {
            ts: 1,
            level: "ERROR".to_string(),
            message: "err".to_string(),
            target: "test".to_string(),
        });
        buffer.push(LogEntry {
            ts: 2,
            level: "INFO".to_string(),
            message: "info".to_string(),
            target: "test".to_string(),
        });
        buffer.push(LogEntry {
            ts: 3,
            level: "WARN".to_string(),
            message: "warn".to_string(),
            target: "test".to_string(),
        });

        // min_level=WARN should include ERROR and WARN, exclude INFO.
        let recent = buffer.recent(10, Some("WARN"), None);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].level, "WARN");
        assert_eq!(recent[1].level, "ERROR");
    }

    #[test]
    fn ring_buffer_search_matches_target_and_level() {
        let buffer = LogBuffer::new();

        buffer.push(LogEntry {
            ts: 1,
            level: "INFO".to_string(),
            message: "access request".to_string(),
            target: "sentirum_lb::proxy::handler".to_string(),
        });
        buffer.push(LogEntry {
            ts: 2,
            level: "WARN".to_string(),
            message: "watcher backoff".to_string(),
            target: "sentirum_lb::consul::watcher".to_string(),
        });

        assert_eq!(buffer.recent(10, None, Some("proxy::handler")).len(), 1);
        assert_eq!(buffer.recent(10, None, Some("warn")).len(), 1);
        assert_eq!(buffer.recent(10, None, Some("backoff"))[0].level, "WARN");
    }

    #[test]
    fn broadcast_receives_pushed_entries() {
        let buffer = LogBuffer::new();
        let mut receiver = buffer.subscribe();

        buffer.push(LogEntry {
            ts: 42,
            level: "INFO".to_string(),
            message: "hello".to_string(),
            target: "test".to_string(),
        });

        let entry = receiver.try_recv().unwrap();
        assert_eq!(entry.message, "hello");
    }

    #[test]
    fn level_order_mapping() {
        assert_eq!(level_order("ERROR"), Some(0));
        assert_eq!(level_order("WARN"), Some(1));
        assert_eq!(level_order("INFO"), Some(2));
        assert_eq!(level_order("DEBUG"), Some(3));
        assert_eq!(level_order("TRACE"), Some(4));
        assert_eq!(level_order("UNKNOWN"), None);
    }
}
