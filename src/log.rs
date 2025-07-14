use std::borrow::Cow;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Instant, SystemTime};

use chrono::{DateTime, Utc};
use file_rotate::FileRotate;
use pyo3::exceptions::{PyException, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyIterator, PyList, PySet, PyString, PyTuple};
use serde_json::{json, Value};

extern "C" {
    fn PyFrame_GetBack(frame: *mut pyo3::ffi::PyFrameObject) -> *mut pyo3::ffi::PyFrameObject;
}

#[derive(Debug)]
struct Message {
    ts: SystemTime,
    elapsed: std::time::Duration,
    level: i32,
    text: String,
    context: Option<Value>,
    exception: Option<ExceptionInfo>,
    frame_info: FrameInfo,
    thread_info: ThreadInfo,
}

#[derive(Debug)]
struct ExceptionInfo {
    exc_type: String,
    exc_value: String,
    traceback: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug)]
struct FrameInfo {
    module_name: Option<String>,
    f_lineno: usize,
    co_name: String,
    co_filename: String,
}

#[derive(Debug)]
struct ThreadInfo {
    id: usize,
    name: String,
}

enum Action {
    SetLevel(i32),
    SetPath(PathBuf),
    Log(Message),
}

#[repr(i32)]
#[derive(Debug)]
enum LogLevel {
    NOTSET = 0,
    DEBUG = 10,
    INFO = 20,
    WARNING = 30,
    ERROR = 40,
    CRITICAL = 50,
}

impl TryFrom<&str> for LogLevel {
    type Error = pyo3::PyErr;
    fn try_from(value: &str) -> PyResult<Self> {
        Ok(match value {
            "NOTSET" => Self::NOTSET,
            "DEBUG" => Self::DEBUG,
            "INFO" => Self::INFO,
            "WARNING" => Self::WARNING,
            "ERROR" => Self::ERROR,
            "CRITICAL" => Self::CRITICAL,
            _ => {
                return Err(PyValueError::new_err(format!(
                    "unknown log level name {}",
                    value
                )))
            }
        })
    }
}

fn level_name(level: i32) -> std::borrow::Cow<'static, str> {
    Cow::from(match level {
        0 => "NOTSET",
        10 => "DEBUG",
        20 => "INFO",
        30 => "WARNING",
        40 => "ERROR",
        50 => "CRITICAL",
        _ => return Cow::from(level.to_string()),
    })
}

fn level_color(level: i32) -> &'static str {
    match level {
        10 => "\x1b[34m\x1b[1m",
        20 => "\x1b[1m",
        30 => "\x1b[33m\x1b[1m",
        40 => "\x1b[31m\x1b[1m",
        50 => "\x1b[41m\x1b[1m",
        _ => "",
    }
}

struct LoggerThread {
    writer: Option<BufWriter<FileRotate<file_rotate::suffix::AppendCount>>>,
    level: i32,
    isatty: bool,
    log_to_stderr: bool,
}

impl LoggerThread {
    fn new() -> Self {
        Self {
            writer: None,
            level: LogLevel::NOTSET as i32,
            isatty: atty::is(atty::Stream::Stdout),
            log_to_stderr: std::env::var_os("AZURE_RESOURCE_GROUP").is_none(),
        }
    }

    fn run(&mut self, rx: mpsc::Receiver<Action>) {
        loop {
            match rx.recv() {
                Ok(action) => self.handle(action),
                Err(_err) => {
                    // TODO: can this happen for any reason other than process shutdown?
                    // eprintln!("crs_rust::Logger shutting down: {:?}", err);
                    break;
                }
            }
        }
    }

    fn handle(&mut self, action: Action) {
        match action {
            Action::Log(msg) => {
                if msg.level < self.level {
                    return;
                }
                let datetime: DateTime<Utc> = msg.ts.into();
                let ts = datetime.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
                let fmt_text = Self::format_message(ts.as_str(), &msg, false);
                if self.log_to_stderr {
                    self.log_stderr(&ts, &fmt_text, &msg);
                }
                self.log_json(&datetime, fmt_text, msg);
            }
            Action::SetPath(path) => {
                let file = FileRotate::new(
                    path,
                    file_rotate::suffix::AppendCount::new(10),
                    file_rotate::ContentLimit::Bytes(4 * 1024 * 1024 * 1024), // 4GB
                    file_rotate::compression::Compression::None,
                    None,
                );
                self.writer = Some(BufWriter::new(file));
            }
            Action::SetLevel(level) => {
                self.level = level;
            }
        }
    }

    fn format_message(ts: &str, msg: &Message, color: bool) -> String {
        let level = level_name(msg.level);
        let module = msg.frame_info.module_name.as_deref().unwrap_or("<unknown>");
        let fmt_msg = if color {
            let color = level_color(msg.level);
            format!(
                "\x1b[32m{timestamp}\x1b[0m | {color}{level:<8}\x1b[0m | \x1b[36m{module}\x1b[0m:\x1b[36m{function}\x1b[0m:\x1b[36m{line}\x1b[0m - {color}{message}\x1b[0m",
                timestamp = ts,
                level = level,
                color = color,
                module = module,
                function = msg.frame_info.co_name,
                line = msg.frame_info.f_lineno,
                message = msg.text
            )
        } else {
            format!(
                "{timestamp} | {level:<8} | {module}:{function}:{line} - {message}",
                timestamp = ts,
                level = level,
                module = module,
                function = msg.frame_info.co_name,
                line = msg.frame_info.f_lineno,
                message = msg.text
            )
        };
        if let Some(tb) = msg.exception.as_ref().and_then(|x| x.traceback.as_ref()) {
            format!("{}\n{}", fmt_msg, tb)
        } else {
            fmt_msg
        }
    }

    fn log_stderr(&self, ts: &str, fmt_text: &str, msg: &Message) {
        if self.isatty {
            let fmt_text = Self::format_message(ts, msg, true);
            eprintln!("{}", fmt_text);
        } else {
            eprintln!("{}", fmt_text);
        }
    }

    fn log_json(&mut self, datetime: &DateTime<Utc>, fmt_text: String, msg: Message) {
        if self.writer.is_none() {
            return;
        }
        let elapsed = msg.elapsed.as_secs();
        let elapsed_repr = {
            let hh = elapsed / 3600;
            let mm = (elapsed % 3600) / 60;
            let ss = elapsed % 60;
            let mu = msg.elapsed.subsec_micros();
            format!("{hh}:{mm:02}:{ss:02}.{mu}")
        };
        let pathbuf = PathBuf::from(&msg.frame_info.co_filename);
        let basename = pathbuf.file_name().map(|x| x.to_string_lossy());

        let ts_unix = msg
            .ts
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|x| x.as_secs_f64())
            .ok();

        let exception_json = msg.exception.map(|x| {
            json!({
                "type": x.exc_type,
                "value": x.exc_value,
                "traceback": x.traceback.is_some(),
            })
        });

        let value = json!({
            "text": fmt_text,
            "record": {
                "elapsed": {
                    "repr": elapsed_repr,
                    "seconds": msg.elapsed.as_secs_f64(),
                },
                "exception": exception_json,
                "extra": msg.context,
                "file": {
                    "name": basename,
                    "path": msg.frame_info.co_filename,
                },
                "function": msg.frame_info.co_name,
                "level": {
                    // "icon": "?",
                    "name": level_name(msg.level),
                    "no": msg.level,
                },
                "line": msg.frame_info.f_lineno,
                "message": msg.text,
                "name": msg.frame_info.module_name,
                "module": msg.frame_info.module_name
                    .as_ref()
                    .map(|x| x.split(".").last().unwrap_or_else(|| x.as_str())),
                "process": {
                    "id": std::process::id(),
                    "name": "MainProcess", // not worried about multiprocessing, but this could be multiprocessing.current_process().name
                },
                "thread": {
                    "id": msg.thread_info.id,
                    "name": msg.thread_info.name,
                },
                "time": {
                    "repr": datetime.to_rfc3339(),
                    "timestamp": ts_unix,
                }
            }
        });
        if let Some(mut file) = self.writer.as_mut() {
            let _ = serde_json::to_writer(&mut file, &value);
            let _ = file.write(b"\n");
        }
    }
}

fn pydict_to_serde(obj: &Bound<'_, PyDict>) -> PyResult<Value> {
    let mut out = serde_json::Map::new();
    for (key, value) in obj.iter() {
        let key: String = key.extract()?;
        let value = py_to_serde(value)?;
        out.insert(key, value);
    }
    Ok(Value::Object(out))
}

fn pyiter_to_serde(obj: Bound<'_, PyIterator>) -> PyResult<Value> {
    let mut out: Vec<Value> = Vec::new();
    for x in obj {
        out.push(py_to_serde(x?)?);
    }
    Ok(Value::Array(out))
}

fn py_to_serde(obj: Bound<'_, PyAny>) -> PyResult<Value> {
    let value = if obj.is_none() {
        Value::Null
    } else if let Ok(value) = obj.extract::<bool>() {
        Value::Bool(value)
    } else if let Ok(value) = obj.extract::<i128>() {
        serde_json::Number::from_i128(value)
            .map(|x| Value::Number(x))
            .unwrap_or_else(|| Value::Null)
    } else if let Ok(value) = obj.extract::<f64>() {
        serde_json::Number::from_f64(value)
            .map(|x| Value::Number(x))
            .unwrap_or_else(|| Value::Null)
    } else if let Ok(value) = obj.extract::<String>() {
        Value::String(value)
    } else if let Ok(value) = obj.downcast::<PyList>() {
        pyiter_to_serde(value.try_iter()?)?
    } else if let Ok(value) = obj.downcast::<PyTuple>() {
        pyiter_to_serde(value.try_iter()?)?
    } else if let Ok(value) = obj.downcast::<PySet>() {
        pyiter_to_serde(value.try_iter()?)?
    } else if let Ok(value) = obj.downcast::<PyDict>() {
        pydict_to_serde(value)?
    } else if let Ok(value) = obj.downcast::<PyException>() {
        Value::String(value.repr()?.to_string())
    } else if let Ok(value) = obj.extract::<PathBuf>() {
        Value::String(value.to_string_lossy().to_string())
    } else {
        let name = obj
            .get_type()
            .name()
            .map(|x| x.to_string())
            .unwrap_or_else(|_| "<unknown>".into());
        Value::String(format!("<opaque {name}>"))
    };
    Ok(value)
}

#[pyclass(module = "crs_rust.log")]
pub struct Logger {
    context_fn: Option<Py<PyAny>>,
    sender: Option<mpsc::Sender<Action>>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
    start_ts: Instant,
    level: i32,
    pytest_mode: bool,
}

impl Drop for Logger {
    fn drop(&mut self) {
        // make sure we flush messages on exit
        // 1. close the sender
        self.sender.take();
        // 2. join the thread
        self.thread_handle.take().map(|x| x.join());
    }
}

impl Logger {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let thread_handle = Self::spawn(rx);
        Self {
            context_fn: None,
            sender: Some(tx),
            thread_handle: Some(thread_handle),
            start_ts: Instant::now(),
            level: LogLevel::NOTSET as i32,
            pytest_mode: false,
        }
    }

    fn spawn(channel: mpsc::Receiver<Action>) -> std::thread::JoinHandle<()> {
        let builder = std::thread::Builder::new().name("crs_rust::Logger".into());
        builder
            .spawn(move || {
                let mut thread = LoggerThread::new();
                thread.run(channel);
            })
            .unwrap()
    }

    fn get_context(
        &self,
        py: Python,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Option<Value>> {
        let ctx = if let Some(cb) = &self.context_fn {
            let pyctx = cb.bind(py).call0()?;
            let pydict = pyctx.downcast::<PyDict>()?;
            Some(pydict_to_serde(pydict)?)
        } else {
            None
        };
        if ctx.is_none() && kwargs.is_none() {
            return Ok(None);
        }
        let mut out = serde_json::Map::new();
        if let Value::Object(obj) = ctx.into() {
            out.extend(obj.into_iter());
        }
        if let Some(kwargs) = kwargs {
            if let Value::Object(obj) = pydict_to_serde(kwargs)? {
                out.extend(obj.into_iter());
            }
        }
        if out.is_empty() {
            return Ok(None);
        }
        Ok(Some(Value::Object(out)))
    }

    fn format_exception_chain(py: Python, exception: Bound<'_, PyAny>) -> PyResult<String> {
        let mut chain: Vec<(Option<&'static str>, Option<Bound<'_, PyAny>>)> = Vec::new();
        let mut exc = exception;
        loop {
            let mut chained_msg: Option<&'static str> = None;
            let mut chained_exc: Option<Bound<'_, PyAny>> = None;

            let cause = exc.getattr("__cause__")?;
            if !cause.is_none() {
                chained_msg = Some(
                    "\n\nThe above exception was the direct cause of the following exception:\n\n",
                );
                chained_exc = Some(cause);
            } else {
                let context = exc.getattr("__context__")?;
                let suppress_context = exc.getattr("__suppress_context__")?;
                if !context.is_none() && !suppress_context.is_truthy()? {
                    chained_msg = Some("\n\nDuring handling of the above exception, another exception occurred:\n\n");
                    chained_exc = Some(context);
                }
            }
            chain.push((chained_msg, Some(exc)));
            match &chained_exc {
                Some(inner) => exc = inner.clone(),
                None => break,
            }
        }
        let mut chunks: Vec<String> = Vec::new();
        for (msg, exc) in chain.into_iter().rev() {
            if let Some(msg) = msg {
                chunks.push(msg.to_owned());
            }
            if let Some(exc) = exc {
                let err = PyErr::from_value(exc);
                let tb = err.traceback(py).and_then(|x| x.format().ok());
                if let Some(tb) = tb {
                    chunks.push(tb);
                }
                chunks.push(err.to_string());
            }
        }
        Ok(chunks.join(""))
    }

    fn get_exception_info(
        &self,
        py: Python,
        exception: Bound<'_, PyAny>,
    ) -> PyResult<ExceptionInfo> {
        let tb = Self::format_exception_chain(py, exception.clone());
        let err = PyErr::from_value(exception);
        let tb = tb.unwrap_or_else(|_| err.to_string());
        Ok(ExceptionInfo {
            exc_type: err.get_type(py).to_string(),
            exc_value: err.value(py).to_string(),
            traceback: Some(tb),
        })
    }

    fn get_message(
        &self,
        py: Python,
        depth: usize,
        level: i32,
        text: &Bound<'_, PyString>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Message> {
        let ts = SystemTime::now();
        let elapsed = self.start_ts.elapsed();
        let context = self.get_context(py, kwargs)?;
        // format text
        let fmt_text: String;
        match kwargs {
            Some(kwargs) => {
                fmt_text = text.call_method("format", (), Some(kwargs))?.extract()?;
            }
            None => {
                fmt_text = text.to_string_lossy().into_owned();
            }
        }
        // get caller function info
        let frame: Bound<'_, PyAny> = unsafe {
            let mut frame = pyo3::ffi::PyEval_GetFrame();
            let mut rframe = Bound::from_borrowed_ptr_or_err(py, frame as *mut _)?;
            for _ in 0..depth {
                if frame.is_null() {
                    return Err(PyRuntimeError::new_err("invalid log() depth="));
                }
                frame = PyFrame_GetBack(frame);
                rframe = Bound::from_owned_ptr_or_err(py, frame as *mut _)?;
            }
            rframe
        };

        let f_globals = frame.getattr("f_globals")?;
        let f_lineno: usize = frame.getattr("f_lineno")?.extract()?;
        let module_name: Option<String> = f_globals
            .get_item("__name__")
            .and_then(|x| x.extract())
            .unwrap_or(None);
        let f_code = frame.getattr("f_code")?;
        let co_name: String = f_code.getattr("co_name")?.extract()?;
        let co_filename: String = f_code.getattr("co_filename")?.extract()?;
        let frame_info = FrameInfo {
            module_name,
            f_lineno,
            co_name,
            co_filename,
        };
        let thread = py.import("threading")?.getattr("current_thread")?.call0()?;
        let thread_info = ThreadInfo {
            id: thread.getattr("native_id")?.extract()?,
            name: thread.getattr("name")?.extract()?,
        };

        Ok(Message {
            ts,
            elapsed,
            level,
            text: fmt_text,
            context,
            exception: None,
            frame_info,
            thread_info,
        })
    }

    fn post_message(&self, py: Python, msg: Message, text: &Bound<'_, PyString>) -> PyResult<()> {
        if self.pytest_mode {
            let datetime: DateTime<Utc> = msg.ts.into();
            let ts = datetime.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            let line = LoggerThread::format_message(&ts, &msg, true);
            let line = format!("{}\n", line);
            py.import("sys")?
                .getattr("stderr")?
                .getattr("write")?
                .call1((line,))?;
            return Ok(());
        }

        if let Some(sender) = &self.sender {
            if let Err(err) = sender.send(Action::Log(msg)) {
                eprintln!(
                    "(crs_rust::Logger) failed to send log message: {} {:?}",
                    err, text
                )
            }
        } else {
            eprintln!(
                "(crs_rust::Logger) failed to send log message: (sender closed) {:?}",
                text
            )
        }
        Ok(())
    }
}

#[pymethods]
impl Logger {
    fn configure(
        &mut self,
        level: Bound<'_, PyAny>,
        path: PathBuf,
        context_fn: Py<PyAny>,
    ) -> PyResult<()> {
        if let Some(sender) = &self.sender {
            let _ = sender.send(Action::SetPath(path));
        }
        self.level = self.set_level(level)?;
        self.context_fn = Some(context_fn);
        Ok(())
    }

    fn set_level(&mut self, level: Bound<'_, PyAny>) -> PyResult<i32> {
        let level = if let Ok(value) = level.extract::<String>() {
            LogLevel::try_from(value.as_str())? as i32
        } else {
            level.extract::<i32>()?
        };
        self.level = level;
        if let Some(sender) = &self.sender {
            let _ = sender.send(Action::SetLevel(level));
        }
        Ok(level)
    }

    fn set_pytest_mode(&mut self) {
        self.pytest_mode = true;
    }

    #[pyo3(signature = (text, **kwargs))]
    fn debug(
        &self,
        py: Python,
        text: &Bound<'_, PyString>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        let level = LogLevel::DEBUG as i32;
        self.log(py, level, text, kwargs)
    }

    #[pyo3(signature = (text, **kwargs))]
    fn info(
        &self,
        py: Python,
        text: &Bound<'_, PyString>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        let level = LogLevel::INFO as i32;
        self.log(py, level, text, kwargs)
    }

    #[pyo3(signature = (text, **kwargs))]
    fn warning(
        &self,
        py: Python,
        text: &Bound<'_, PyString>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        let level = LogLevel::WARNING as i32;
        self.log(py, level, text, kwargs)
    }

    #[pyo3(signature = (text, **kwargs))]
    fn error(
        &self,
        py: Python,
        text: &Bound<'_, PyString>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        let level = LogLevel::ERROR as i32;
        self.log(py, level, text, kwargs)
    }

    #[pyo3(signature = (text, **kwargs))]
    fn critical(
        &self,
        py: Python,
        text: &Bound<'_, PyString>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        let level = LogLevel::CRITICAL as i32;
        self.log(py, level, text, kwargs)
    }

    #[pyo3(signature = (text, exception=None, **kwargs))]
    fn exception(
        &self,
        py: Python,
        text: &Bound<'_, PyString>,
        exception: Option<Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        let level = LogLevel::ERROR as i32;
        if level < self.level {
            return Ok(());
        }
        let mut msg = self.get_message(py, 0, level, text, kwargs)?;
        let exception = match exception {
            Some(exc) => Some(exc),
            None => {
                let exc = py.import("sys")?.getattr("exception")?.call0()?;
                if exc.is_none() {
                    None
                } else {
                    Some(exc)
                }
            }
        };
        if let Some(exception) = exception {
            msg.exception = Some(self.get_exception_info(py, exception)?);
        }
        self.post_message(py, msg, text)?;
        Ok(())
    }

    #[pyo3(signature = (level, text, depth, exception))]
    fn forward_log(
        &self,
        py: Python,
        level: i32,
        text: &Bound<'_, PyString>,
        depth: usize,
        exception: Option<Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        if level < self.level {
            return Ok(());
        }
        let mut msg = self.get_message(py, depth, level, text, None)?;
        if let Some(exc) = exception {
            msg.exception = Some(self.get_exception_info(py, exc)?);
        }
        self.post_message(py, msg, text)?;
        Ok(())
    }

    #[pyo3(signature = (level, text, **kwargs))]
    fn log(
        &self,
        py: Python,
        level: i32,
        text: &Bound<'_, PyString>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        if level < self.level {
            return Ok(());
        }
        let msg = self.get_message(py, 0, level, text, kwargs)?;
        self.post_message(py, msg, text)?;
        Ok(())
    }
}

#[pymodule]
pub(crate) fn log(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Logger>()?;
    Ok(())
}
