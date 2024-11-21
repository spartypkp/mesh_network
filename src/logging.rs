// src/logging.rs
use serde_json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Log level for messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

/// A structured log entry
#[derive(Debug, Clone)]
pub struct LogEntry {
    timestamp: u64,
    level: LogLevel,
    component: String,
    message: String,
    sequence: usize,
    metadata: Option<serde_json::Value>,
}

impl LogEntry {
    pub fn new(
        level: LogLevel,
        component: impl Into<String>,
        message: impl Into<String>,
        metadata: Option<serde_json::Value>,
    ) -> Self {
        static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            level,
            component: component.into(),
            message: message.into(),
            sequence: SEQUENCE.fetch_add(1, Ordering::SeqCst),
            metadata,
        }
    }
}

/// Logger configuration
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub min_level: LogLevel,
    pub buffer_size: usize,
    pub include_metadata: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            min_level: LogLevel::Info,
            buffer_size: 1000,
            include_metadata: true,
        }
    }
}

/// Async logger that can be shared across threads
#[derive(Debug, Clone)]
pub struct Logger {
    config: LogConfig,
    sender: mpsc::Sender<LogEntry>,
}

impl Logger {
    pub async fn new(config: LogConfig) -> (Self, LogReceiver) {
        let (sender, receiver) = mpsc::channel(config.buffer_size);

        (Self { config, sender }, LogReceiver { receiver })
    }

    pub async fn log(
        &self,
        level: LogLevel,
        component: impl Into<String>,
        message: impl Into<String>,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), mpsc::error::SendError<LogEntry>> {
        if level >= self.config.min_level {
            let entry = LogEntry::new(level, component, message, metadata);
            self.sender.send(entry).await
        } else {
            Ok(())
        }
    }

    // Convenience methods
    pub async fn debug(&self, component: impl Into<String>, message: impl Into<String>) {
        let _ = self.log(LogLevel::Debug, component, message, None).await;
    }

    pub async fn info(&self, component: impl Into<String>, message: impl Into<String>) {
        let _ = self.log(LogLevel::Info, component, message, None).await;
    }

    pub async fn warning(&self, component: impl Into<String>, message: impl Into<String>) {
        let _ = self.log(LogLevel::Warning, component, message, None).await;
    }

    pub async fn error(&self, component: impl Into<String>, message: impl Into<String>) {
        let _ = self.log(LogLevel::Error, component, message, None).await;
    }
}

/// Receives and processes log entries
pub struct LogReceiver {
    receiver: mpsc::Receiver<LogEntry>,
}

impl LogReceiver {
    pub async fn run(mut self) {
        while let Some(entry) = self.receiver.recv().await {
            // For now, just print to stdout
            // In a real implementation, this would write to file/database/etc.
            println!(
                "[{:010}][{:?}][{}] {}",
                entry.sequence, entry.level, entry.component, entry.message
            );

            if let Some(metadata) = entry.metadata {
                println!("  Metadata: {}", metadata);
            }
        }
    }
}
