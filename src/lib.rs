mod http;
mod log;
mod metrics;
mod patch;
mod path_suffix;

use pyo3::prelude::*;

#[pymodule]
pub fn crs_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let http_mod = PyModule::new(m.py(), "crs_rust.http")?;
    http::http(&http_mod)?;
    m.add("http", http_mod)?;

    let log_mod = PyModule::new(m.py(), "crs_rust.log")?;
    log::log(&log_mod)?;
    m.add("log", log_mod)?;
    m.add("logger", Py::new(m.py(), log::Logger::new())?)?;

    m.add("sw_align", wrap_pyfunction!(patch::sw_align, m)?)?;
    m.add("compute_edit", wrap_pyfunction!(patch::compute_edit, m)?)?;
    m.add_class::<patch::Edit>()?;

    m.add_class::<metrics::Metrics>()?;
    m.add_class::<metrics::Counter>()?;
    m.add_class::<metrics::Gauge>()?;
    m.add_class::<path_suffix::PathSuffixTree>()?;
    Ok(())
}
