use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::{Component, Path};

const MAX_SUGGEST: usize = 10;

#[derive(Default)]
struct Node {
    children: HashMap<String, Node>,
}

impl Node {
    fn from_json_bytes(raw: &[u8]) -> PyResult<Self> {
        let v: Value = serde_json::from_slice(raw)
            .map_err(|e| PyValueError::new_err(format!("invalid JSON: {e}")))?;
        match v {
            Value::Object(m) => Self::from_map(&m),
            _ => Err(PyValueError::new_err("root of tree must be a JSON object")),
        }
    }

    fn from_map(m: &Map<String, Value>) -> PyResult<Self> {
        let mut children = HashMap::with_capacity(m.len());
        for (k, v) in m {
            let child = match v {
                Value::Object(sub) => Self::from_map(sub)?,
                _ => {
                    return Err(PyValueError::new_err(
                        "tree JSON may only contain nested objects",
                    ))
                }
            };
            children.insert(k.clone(), child);
        }
        Ok(Node { children })
    }

    fn is_unique(&self) -> bool {
        self.children.is_empty()
            || (self.children.len() == 1 && self.children.values().next().unwrap().is_unique())
    }

    fn collect_suffixes(&self, prefix: &str, out: &mut Vec<String>) {
        if self.children.is_empty() {
            out.push(if prefix.is_empty() {
                "./".into()
            } else {
                prefix.into()
            });
            return;
        }
        for (k, child) in &self.children {
            let new_p = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{k}/{prefix}")
            };
            child.collect_suffixes(&new_p, out);
        }
    }

    fn similar_paths(&self, ready_suffix: &str) -> Vec<String> {
        if ready_suffix.is_empty() {
            return Vec::new();
        }
        let mut v = Vec::new();
        self.collect_suffixes(ready_suffix, &mut v);
        if v.len() > MAX_SUGGEST {
            v.truncate(MAX_SUGGEST);
        }
        v
    }
}

fn comps(p: &str) -> Vec<String> {
    Path::new(p)
        .components()
        .filter_map(|c| match c {
            Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

fn msg_missing(bad: &str, similar: &[String]) -> String {
    if similar.is_empty() {
        let fname = Path::new(bad).file_name().unwrap().to_string_lossy();
        format!("path '{bad}' does not exist in directory tree. In fact, no files named '{fname}' are available.")
    } else {
        format!(
            "path '{bad}' does not exist in directory tree. Similar paths: {}",
            similar.join(",")
        )
    }
}

fn raise_crserror(py: Python<'_>, msg: &str) -> PyErr {
    if let Ok(m) = py.import("crs.common.types") {
        if let Ok(cls) = m.getattr("CRSError") {
            if let Ok(obj) = cls.call1((msg,)) {
                return PyErr::from_value(obj);
            }
        }
    }
    PyValueError::new_err(msg.to_owned())
}

type NormEntry = Result<String, String>; // Ok(unique suffix) | Err(msg)
type CheckEntry = Result<(), String>; // Ok() | Err(msg)

#[pyclass(module = "crs_rust.path_suffix")]
pub struct PathSuffixTree {
    root: Node,
    norm_cache: HashMap<String, NormEntry>,
    check_cache: HashMap<String, CheckEntry>,
}

#[pymethods]
impl PathSuffixTree {
    #[new]
    fn new(buffer: Vec<u8>) -> PyResult<Self> {
        Ok(Self {
            root: Node::from_json_bytes(&buffer)?,
            norm_cache: HashMap::new(),
            check_cache: HashMap::new(),
        })
    }

    fn normalize_path<'py>(&'py mut self, py: Python<'py>, path: &str) -> PyResult<String> {
        if let Some(entry) = self.norm_cache.get(path) {
            return match entry {
                Ok(s) => Ok(s.clone()),
                Err(msg) => Err(raise_crserror(py, msg)),
            };
        }

        let parts = comps(path);
        if parts.is_empty() {
            self.norm_cache.insert(path.to_owned(), Ok("./".into()));
            return Ok("./".into());
        }

        let mut suffix = String::new();
        let mut cur = &self.root;

        for part in parts.iter().rev() {
            match cur.children.get(part) {
                Some(next) => {
                    suffix = if suffix.is_empty() {
                        part.clone()
                    } else {
                        format!("{part}/{suffix}")
                    };
                    cur = next;
                    if cur.is_unique() {
                        break;
                    }
                }
                None => {
                    let msg = msg_missing(path, &cur.similar_paths(&suffix));
                    self.norm_cache.insert(path.to_owned(), Err(msg.clone()));
                    return Err(raise_crserror(py, &msg));
                }
            }
        }

        self.norm_cache.insert(path.to_owned(), Ok(suffix.clone()));
        Ok(suffix)
    }

    fn check_path<'py>(&'py mut self, py: Python<'py>, path: &str) -> PyResult<()> {
        if let Some(entry) = self.check_cache.get(path) {
            return match entry {
                Ok(_) => Ok(()),
                Err(msg) => Err(raise_crserror(py, msg)),
            };
        }

        let norm = match self.normalize_path(py, path) {
            Ok(s) => s,
            Err(e) => {
                // normalize_path already cached failure
                return Err(e);
            }
        };

        let full = self.get_full_paths(py, &norm)?;
        if full.len() == 1 && full[0] == path {
            self.check_cache.insert(path.to_owned(), Ok(()));
            Ok(())
        } else {
            let msg = msg_missing(path, &full);
            self.check_cache.insert(path.to_owned(), Err(msg.clone()));
            Err(raise_crserror(py, &msg))
        }
    }

    fn get_full_paths(&self, py: Python<'_>, partial: &str) -> PyResult<Vec<String>> {
        let parts = comps(partial);
        let mut suffix = String::new();
        let mut cur = &self.root;

        for part in parts.iter().rev() {
            match cur.children.get(part) {
                Some(next) => {
                    suffix = if suffix.is_empty() {
                        part.clone()
                    } else {
                        format!("{part}/{suffix}")
                    };
                    cur = next;
                }
                None => {
                    let msg = msg_missing(partial, &cur.similar_paths(&suffix));
                    return Err(raise_crserror(py, &msg));
                }
            }
        }

        let mut deeper = Vec::new();
        cur.collect_suffixes("", &mut deeper);

        let mut out = Vec::with_capacity(deeper.len());
        for s in deeper {
            if s == "./" {
                out.push(suffix.clone());
            } else if suffix.is_empty() {
                out.push(s);
            } else {
                out.push(format!("{s}/{suffix}"));
            }
        }
        Ok(out)
    }

    fn all_paths(&self) -> Vec<String> {
        let mut v = Vec::new();
        self.root.collect_suffixes("", &mut v);
        v
    }
}
