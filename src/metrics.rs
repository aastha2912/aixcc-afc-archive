use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use influxdb::{Client, Timestamp, WriteQuery};
use pyo3::prelude::*;
use tokio::sync::mpsc::{Sender, channel};

fn query_with_tags(name: &str, tags1: &HashMap<String, String>, tags2: Option<&HashMap<String, String>>) -> WriteQuery {
    let ts = Timestamp::Nanoseconds(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos());
    let mut query = WriteQuery::new(ts, name);
    for (k, v) in tags1.iter() {
        if v != "" {
            query = query.add_tag(k, v.as_str());
        }
    }
    if let Some(tags2) = tags2 {
        for (k, v) in tags2.iter() {
            if v != "" {
                query = query.add_tag(k, v.as_str());
            }
        }
    }
    query
}

#[derive(Debug, Default)]
struct DropDebounce {
    count: usize,
    last: Option<Instant>,
}

impl DropDebounce {
    fn inc(&mut self, err: impl std::error::Error) {
        self.count += 1;
        let now = Instant::now();
        let do_print = if let Some(last) = self.last {
            if now.duration_since(last).as_secs_f64() >= 1.0 {
                true
            } else {
                false
            }
        } else {
            true
        };
        if do_print {
            eprintln!("warning: dropping metric ({}) metrics ({:?})", self.count, err);
        }
        self.last = Some(now);
    }
}

#[pyclass]
pub struct Metrics {
    runtime: tokio::runtime::Runtime,
    tx: Option<Sender<WriteQuery>>,
    tags: HashMap<String, String>,
    drop: DropDebounce,
}

#[pymethods]
impl Metrics {
    #[new]
    #[pyo3(signature = (url, bucket, tags))]
    fn new(url: Option<String>, bucket: String, tags: HashMap<String, String>) -> PyResult<Self> {
        let (tx, mut rx) = channel(50_000);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .enable_time()
            .enable_io()
            .thread_name("MetricsThread")
            .on_thread_start(|| pyo3::prepare_freethreaded_python())
            .build()
            .unwrap();
        let mut obj = Self {
            runtime,
            tx: Some(tx),
            tags,
            drop: Default::default(),
        };
        if let Some(url) = url {
            obj.runtime.spawn(async move {
                let client = Client::new(url, bucket);
                loop {
                    if let Some(query) = rx.recv().await {
                        if let Err(err) = client.query(query).await {
                            eprintln!("metrics submit error: {err:?}");
                        }
                    } else {
                        // channel is disconnected
                        break;
                    }
                }
            });
        } else {
            obj.tx = None;
        }
        Ok(obj)
    }

    fn create_counter(&self, name: &str) -> Counter {
        Counter::new(name, self.tags.clone(), self.tx.clone())
    }

    fn create_gauge(&self, name: &str) -> Gauge {
        Gauge::new(name, self.tags.clone(), self.tx.clone())
    }

    #[pyo3(signature = (name, fields, tags=None))]
    fn report(&mut self, name: &str, fields: HashMap<String, f64>, tags: Option<HashMap<String, String>>) -> PyResult<()> {
        let mut query = query_with_tags(name, &self.tags, tags.as_ref());
        for (k, v) in fields.iter() {
            query = query.add_field(k, v);
        }
        if let Some(tx) = &self.tx {
            if let Err(err) = tx.try_send(query) {
                self.drop.inc(err);
            }
        }
        Ok(())
    }
}

#[pyclass]
pub struct Counter {
    name: String,
    tx: Option<Sender<WriteQuery>>,
    tags: HashMap<String, String>,
    values: HashMap<String, f64>,
    drop: DropDebounce,
}

impl Counter {
    fn new(name: &str, tags: HashMap<String, String>, tx: Option<Sender<WriteQuery>>) -> Self {
        Self {
            name: name.to_owned(),
            tags,
            tx,
            values: HashMap::new(),
            drop: DropDebounce::default(),
        }
    }
}

#[pymethods]
impl Counter {
    #[pyo3(signature = (value, tags=None))]
    fn add(&mut self, value: f64, tags: Option<HashMap<String, String>>) -> PyResult<()> {
        let query = query_with_tags(&self.name, &self.tags, tags.as_ref());

        let key = match tags {
            Some(tags) => {
                let mut taglist: Vec<(String, String)> = tags.into_iter().collect();
                taglist.sort_by(|a, b| a.0.cmp(&b.0));
                taglist.into_iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<String>>()
                    .join(",")
            }
            None => "".into(),
        };
        let count: f64;
        if let Some(old_value) = self.values.get_mut(&key) {
            count = *old_value + value;
            *old_value = count;
        } else {
            count = value;
            self.values.insert(key, value);
        }

        let query = query.add_field("counter", count);
        if let Some(tx) = &self.tx {
            if let Err(err) = tx.try_send(query) {
                self.drop.inc(err);
            }
        }
        Ok(())
    }
}

#[pyclass]
pub struct Gauge {
    name: String,
    tx: Option<Sender<WriteQuery>>,
    tags: HashMap<String, String>,
    drop: DropDebounce,
}

impl Gauge {
    fn new(name: &str, tags: HashMap<String, String>, tx: Option<Sender<WriteQuery>>) -> Self {
        Self {
            name: name.to_owned(),
            tags,
            tx,
            drop: DropDebounce::default(),
        }
    }
}

#[pymethods]
impl Gauge {
    #[pyo3(signature = (value, tags=None))]
    fn set(&mut self, value: f64, tags: Option<HashMap<String, String>>) -> PyResult<()> {
        let query = query_with_tags(&self.name, &self.tags, tags.as_ref());
        let query = query.add_field("gauge", value);
        if let Some(tx) = &self.tx {
            if let Err(err) = tx.try_send(query) {
                self.drop.inc(err);
            }
        }
        Ok(())
    }
}
