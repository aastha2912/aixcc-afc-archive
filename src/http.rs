use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyBytes, PyDict};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;

#[pyclass(module = "crs_rust.http")]
struct Client {
    runtime: Runtime,
    client: Option<Arc<reqwest::Client>>,
    semaphore: Arc<Semaphore>,

    _py_httpx: Py<PyModule>,
    py_httpx_response: Py<PyAny>,
    py_httpx_headers: Py<PyAny>,
    py_asyncio: Py<PyModule>,
}

const MAX_CONCURRENT: usize = 5_000;

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (**_kwargs))]
    fn new(py: Python, _kwargs: Option<Bound<'_, PyDict>>) -> PyResult<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .enable_time()
            .enable_io()
            .thread_name("http.Client")
            .on_thread_start(|| pyo3::prepare_freethreaded_python())
            .build()
            .unwrap();
        let mut builder = reqwest::ClientBuilder::new();
        builder = builder
            .connect_timeout(Duration::from_secs_f32(5.0))
            .read_timeout(Duration::from_secs_f32(600.0))
            .timeout(Duration::from_secs_f32(600.0))
            .pool_idle_timeout(Duration::from_secs_f32(600.0));
        let client = builder
            .build()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;

        let py_httpx = py.import("httpx")?;
        let py_asyncio = py.import("asyncio")?;
        let py_httpx_response = py_httpx.getattr("Response")?.unbind();
        let py_httpx_headers = py_httpx.getattr("Headers")?.unbind();
        Ok(Client {
            runtime,
            client: Some(Arc::new(client)),
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT)),

            _py_httpx: py_httpx.unbind(),
            py_httpx_response,
            py_httpx_headers,

            py_asyncio: py_asyncio.unbind(),
        })
    }

    #[getter]
    fn is_closed(&self) -> bool {
        self.client.is_none()
    }

    fn close(&mut self) {
        self.client.take();
        self.semaphore.close();
    }

    #[pyo3(signature = (hreq, *))]
    fn request(&self, py: Python, hreq: Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let client = self
            .client
            .as_ref()
            .map(|x| x.clone())
            .ok_or_else(|| PyRuntimeError::new_err("client is closed"))?;
        let semaphore = self.semaphore.clone();

        let method: String = hreq.getattr("method")?.extract()?;
        let url: String = hreq.getattr("url")?.to_string();

        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| PyRuntimeError::new_err("invalid HTTP method"))?;
        let mut builder = client.request(method, url);

        let mut req_header_map = reqwest::header::HeaderMap::new();
        let req_header_vec: Vec<_> = hreq
            .getattr("headers")?
            .call_method0("multi_items")?
            .try_iter()?
            .map(|x| x.and_then(|y| y.extract::<(String, String)>()))
            .collect::<PyResult<_>>()?;
        for (k, v) in req_header_vec.into_iter() {
            let value = reqwest::header::HeaderValue::from_str(&v)
                .map_err(|err| PyValueError::new_err(err.to_string()))?;
            let key = reqwest::header::HeaderName::from_bytes(k.as_bytes())
                .map_err(|err| PyValueError::new_err(err.to_string()))?;
            req_header_map.insert(key, value);
        }
        builder = builder.headers(req_header_map);

        let stream = hreq.getattr("stream")?;
        if let Ok(it) = stream.try_iter() {
            for x in it {
                let bytes = x?.downcast_into::<PyBytes>()?;
                builder = builder.body(bytes.as_bytes().to_owned());
                break;
            }
        }

        let request = builder
            .build()
            .map_err(|_| PyRuntimeError::new_err("failed to make request"))?;

        let runloop = self
            .py_asyncio
            .bind(py)
            .getattr("get_running_loop")?
            .call0()?;
        let future = runloop.call_method0("create_future")?;
        let inner_runloop = runloop.unbind();
        let set_result = future.getattr("set_result")?.unbind();
        let set_exception = future.getattr("set_exception")?.unbind();
        let inner_future = future.clone().unbind();
        let hreq = hreq.unbind();

        let httpx_response = self.py_httpx_response.clone_ref(py);
        let httpx_headers = self.py_httpx_headers.clone_ref(py);

        self.runtime.spawn(async move {
            let permit =
                tokio::time::timeout(Duration::from_secs_f64(60.0), semaphore.acquire()).await;
            let rs_response = match permit {
                Ok(_) => client
                    .execute(request)
                    .await
                    .map_err(|err| PyRuntimeError::new_err(err.to_string())),
                Err(_) => Err(PyRuntimeError::new_err(
                    "failed to acquire request semaphore",
                )),
            };
            let result = match rs_response {
                Ok(rs_response) => {
                    let rs_status = rs_response.status();
                    let rs_headers: Vec<_> = rs_response
                        .headers()
                        .iter()
                        .map(|(name, value)| {
                            (name.as_str().to_owned(), value.as_bytes().to_owned())
                        })
                        .collect();
                    let rs_body = rs_response
                        .bytes()
                        .await
                        .map_err(|err| PyRuntimeError::new_err(err.to_string()));

                    Python::with_gil(|py| -> PyResult<()> {
                        let headers = httpx_headers.bind(py).call1((rs_headers,))?;
                        let body =
                            rs_body.map_err(|_| PyRuntimeError::new_err("failed to load body"))?;
                        let kwargs = [
                            (
                                "status_code",
                                &rs_status.as_u16().into_pyobject(py)?.into_any(),
                            ),
                            ("headers", &headers),
                            ("content", &body.into_pyobject(py)?),
                            ("request", hreq.bind(py)),
                        ]
                        .into_py_dict(py)?;
                        let response = httpx_response.call(py, (), Some(&kwargs))?;
                        if !inner_future
                            .bind(py)
                            .call_method0("done")
                            .and_then(|x| x.extract::<bool>())
                            .unwrap_or(false)
                        {
                            inner_runloop
                                .bind(py)
                                .call_method1("call_soon_threadsafe", (set_result, response))
                                .unwrap();
                        }
                        Ok(())
                    })
                }
                Err(err) => Err(PyRuntimeError::new_err(err.to_string())),
            };
            match result {
                Ok(()) => (),
                Err(err) => Python::with_gil(|py| {
                    if !inner_future
                        .bind(py)
                        .call_method0("done")
                        .and_then(|x| x.extract::<bool>())
                        .unwrap_or(false)
                    {
                        inner_runloop
                            .bind(py)
                            .call_method1("call_soon_threadsafe", (set_exception, err))
                            .unwrap();
                    }
                }),
            }
        });
        Ok(future.unbind())
    }
}

#[pymodule]
pub(crate) fn http(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Client>()?;
    Ok(())
}
