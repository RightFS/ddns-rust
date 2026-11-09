use chrono::Utc;
use serde::Serialize;
use serde_json::{Map, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{EnvFilter, Layer, Registry, layer::Context, prelude::*, reload};

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
    pub fields: Map<String, Value>,
}
#[derive(Clone)]
pub struct Logs(pub Arc<Mutex<VecDeque<LogEntry>>>);
#[derive(Clone)]
pub struct LogControl {
    pub logs: Logs,
    pub filter: reload::Handle<EnvFilter, Registry>,
}
struct Visitor(Map<String, Value>);
impl Visit for Visitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().into(), Value::String(format!("{value:?}")));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0
            .insert(field.name().into(), Value::String(value.into()));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), Value::from(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().into(), Value::from(value));
    }
}
impl<S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>> Layer<S> for Logs {
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let mut visitor = Visitor(Map::new());
        attributes.record(&mut visitor);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(visitor);
        }
    }
    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id)
            && let Some(visitor) = span.extensions_mut().get_mut::<Visitor>()
        {
            values.record(visitor);
        }
    }
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut visitor = Visitor(Map::new());
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if let Some(fields) = span.extensions().get::<Visitor>() {
                    visitor.0.extend(fields.0.clone());
                }
            }
        }
        event.record(&mut visitor);
        let message = visitor
            .0
            .remove("message")
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let entry = LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: event.metadata().level().as_str().to_ascii_lowercase(),
            message,
            fields: visitor.0,
        };
        if let Ok(mut entries) = self.0.lock() {
            if entries.len() >= 1000 {
                entries.pop_front();
            }
            entries.push_back(entry);
        }
    }
}
pub fn filter(level: &str) -> EnvFilter {
    EnvFilter::new(format!("off,ddns_rust={level}"))
}
pub fn init(level: &str) -> Result<LogControl, String> {
    let logs = Logs(Arc::new(Mutex::new(VecDeque::new())));
    let (layer, handle) = reload::Layer::new(filter(level));
    tracing_subscriber::registry()
        .with(layer)
        .with(logs.clone())
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::stderr),
        )
        .try_init()
        .map_err(|e| e.to_string())?;
    Ok(LogControl {
        logs,
        filter: handle,
    })
}
impl Logs {
    pub fn entries(&self, level: Option<&str>, search: Option<&str>) -> Vec<LogEntry> {
        fn rank(level: &str) -> u8 {
            match level {
                "trace" => 0,
                "debug" => 1,
                "info" => 2,
                "warn" => 3,
                _ => 4,
            }
        }
        let search = search.unwrap_or("").to_ascii_lowercase();
        self.0
            .lock()
            .map(|logs| {
                logs.iter()
                    .filter(|e| {
                        level.is_none_or(|l| rank(&e.level) >= rank(l))
                            && (search.is_empty()
                                || format!(
                                    "{} {}",
                                    e.message,
                                    serde_json::to_string(&e.fields).unwrap_or_default()
                                )
                                .to_ascii_lowercase()
                                .contains(&search))
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ring_buffer_and_span_context() {
        let logs = Logs(Arc::new(Mutex::new(VecDeque::new())));
        let subscriber = tracing_subscriber::registry().with(logs.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("test_run", run_id = "correlation-123", record = "home");
            let _guard = span.enter();
            for index in 0..1010 {
                tracing::info!(index, "Bounded event");
            }
            tracing::error!(code = "ProviderFailure", "Failure detail");
        });
        assert_eq!(logs.entries(None, None).len(), 1000);
        let failures = logs.entries(Some("error"), Some("correlation-123"));
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].fields["record"], "home");
        assert_eq!(failures[0].message, "Failure detail");
    }
}
