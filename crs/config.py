"""
Set up API keys and the project defaults for MODEL and SMALLMODEL
Also set up the root path of the crs folder so we can load non-python stuff
The SMALLMODEL will be used for "simple" requests (like summarizing text)
"""

from contextvars import ContextVar
from datetime import datetime
from crs.common.aio import Path
from pydantic import TypeAdapter
from typing import Any
import inspect
import logging
import os
import pathlib
import tomllib

import litellm

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider, AlwaysOffExemplarFilter
from opentelemetry.sdk.metrics.export import MetricReader, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
import opentelemetry
import opentelemetry.metrics

from crs.agents.agent_meta import running_agent, running_tool_call
from crs.common.workdb_meta import cur_job_id
import crs_rust

CRSROOT = Path(__file__).parent

THEORI_COMPILE = CRSROOT / ".." / "utils" / "theori_compile.sh"
PATH_SUFFIX_TREE = CRSROOT / ".." / "utils" / "path_suffix_tree.py"
CRS_LOAD_OPTIONS = CRSROOT / ".." / "utils" / "load_options.sh"
CRS_DEDUP_MON = CRSROOT / ".." / "utils" / "dedup_mon.py"
LCOV_PARSER = CRSROOT / ".." / "utils" / "lcov_parser/target/x86_64-unknown-linux-musl/release/lcov_parser"
JACOCO_PARSER = CRSROOT / ".." / "utils" / "jacoco_parser/target/x86_64-unknown-linux-musl/release/jacoco_parser"
CORPUS_SAMPLE = CRSROOT / ".." / "external" / "corpus" / "sample.tar.xz"
BEAR_PATH = CRSROOT / ".." / "external" / "bear"
LLVM_COV = CRSROOT / ".." / "external" / "llvm-cov" / "llvm-cov"
CRS_GITATTRIBUTES = CRSROOT / "gitattributes"
CRS_UNPACK_GIT = CRSROOT / "../utils/unpack_git.sh"
CRS_HARNESS_MATCH = CRSROOT / "../utils/harness_match.py"

DATA_DIR = Path(os.getenv("DATA_DIR", CRSROOT / ".." / "data"))

CACHE_DIR = Path(os.getenv("CACHE_DIR", "/tmp"))

SERIALIZE_AGENTS = bool(os.getenv("SERIALIZE_AGENTS", False))

# azure
REGISTRY_NAME = os.getenv("CRS_REGISTRY_NAME")
REGISTRY_DOMAIN = os.getenv("CRS_REGISTRY_DOMAIN")

DEBUG = False
MAX_ERROR_OUTPUT = 2048

# Optional spend limit for LLM calls (USD) within a single process.
# Intended usage: run one workflow per process (e.g., one ARVO ID).
# This local/dev default is intentionally low to cap spend unless overridden.
try:
    LLM_BUDGET_USD = float(os.getenv("CRS_LLM_BUDGET_USD", "0.10"))
except ValueError:
    LLM_BUDGET_USD = 0.10

OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
OTEL_TELEGRAF_ENDPOINT = os.getenv("OTEL_TELEGRAF_ENDPOINT")
TRACING = bool(OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_TELEGRAF_ENDPOINT)
# TELEGRAF = bool(OTEL_TELEGRAF_ENDPOINT)
CRS_SERVICE_NAME = os.getenv("CRS_SERVICE_NAME", "roboduck")
if TRACING:
    resource = Resource(attributes={"service.name": CRS_SERVICE_NAME})
    trace_provider = TracerProvider(resource=resource)

    metric_readers: list[MetricReader] = []
    for endpoint in [OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_TELEGRAF_ENDPOINT]:
        if not endpoint:
            continue

        insecure = (endpoint == OTEL_TELEGRAF_ENDPOINT)

        span_exporter = OTLPSpanExporter(endpoint, insecure=insecure)
        span_processor = BatchSpanProcessor(span_exporter, max_queue_size=65536, export_timeout_millis=4000) # type: ignore
        trace_provider.add_span_processor(span_processor)

        metric_exporter = OTLPMetricExporter(endpoint, insecure=insecure, max_export_batch_size=5000)
        metric_reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=1000, export_timeout_millis=4000) # type: ignore
        metric_readers.append(metric_reader)

    opentelemetry.exporter.otlp.proto.grpc.exporter.logger.disabled = True # type: ignore
    meter_provider = MeterProvider(metric_readers=metric_readers, exemplar_filter=AlwaysOffExemplarFilter(), resource=resource)
    opentelemetry.metrics.set_meter_provider(meter_provider)
    trace.set_tracer_provider(trace_provider)
else:
    trace.set_tracer_provider(trace.NoOpTracerProvider())

INFLUXDB_ENDPOINT = os.getenv("INFLUXDB_ENDPOINT")
TELEGRAF = bool(INFLUXDB_ENDPOINT)

telem_tracer = trace.get_tracer(__name__)
metrics = crs_rust.Metrics(INFLUXDB_ENDPOINT, "aixcc", tags={
    "pid": str(os.getpid()),
    "service": CRS_SERVICE_NAME,
})

# allows litellm to modify parameters in certain cases
# useful example: passing system prompts to claude-3 API
litellm.modify_params = True
litellm.suppress_debug_info = True
litellm.drop_params = True

# litellm==1.67.2 (pinned in pyproject.toml) predates GPT-5.6 and has no
# built-in pricing for it, so litellm.get_model_info()/context-window checks
# would fail without this. Values below are the short-context (<=272K
# prompt tokens) tier from OpenAI's official docs
# (developers.openai.com/api/docs/models/gpt-5.6-sol): $5/1M input, $0.50/1M
# cached input, $30/1M output tokens. GPT-5.6 also bills a long-context
# surcharge above that threshold (2x input/1.5x output) that a flat
# litellm.register_model() entry can't express -- the cost actually charged
# against CRS_LLM_BUDGET_USD is computed per-call with tier awareness in
# crs/common/llm_api.py's _tiered_completion_cost(); this registration is
# the fallback/metadata source (provider, context window) only.
litellm.register_model({
    "gpt-5.6-sol": {
        "input_cost_per_token": 5e-06,
        "output_cost_per_token": 3e-05,
        "cache_read_input_token_cost": 5e-07,
        "max_input_tokens": 922_000,
        "max_output_tokens": 128_000,
        "max_tokens": 1_050_000,
        "litellm_provider": "openai",
        "mode": "chat",
    }
})

# API auth for AIxCC services
CAPI_URL = os.environ.get("CAPI_URL") or "http://localhost:1323"
CAPI_ID = os.environ.get("CAPI_ID") or "11111111-1111-1111-1111-111111111111"
CAPI_TOKEN = os.environ.get("CAPI_TOKEN") or "secret"

# blob storage root
CRS_BLOB_ENDPOINT = os.environ.get("CRS_BLOB_ENDPOINT") or "https://de6543ab956de244.blob.core.windows.net"

env_tokens = [
    ("ANTHROPIC_API_KEY", "anthropic-token"),
    ("OPENAI_API_KEY", "openai-token"),
    ("GEMINI_API_KEY", "gemini-token"),
    ("AZURE_API_KEY", "azure-token"),
    ("AZURE_API_BASE", "azure-api"),
    ("AZURE_AI_API_KEY", "azure-ai-token"),
    ("AZURE_AI_API_BASE", "azure-ai-api"),
]
TOKENS_ETC = Path(pathlib.Path((CRSROOT / "../tokens_etc")).absolute())
for env_var, filename in env_tokens:
    if not os.environ.get(env_var):
        with open(TOKENS_ETC / filename) as f:
            os.environ[env_var] = f.read().strip()

_ = os.environ.setdefault("AZURE_API_VERSION", "2024-12-01-preview")
_ = os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", (TOKENS_ETC / "application_default_credentials.json").as_posix())

# for anthropic models
HEADERS = {'anthropic-beta': 'tools-2024-05-16'}

ModelMap = dict[str, list[str]]
# default model configurations
def parse_model_map(path: Path | str) -> ModelMap:
    return TypeAdapter(ModelMap).validate_python(tomllib.load(open(path, "rb")))
_default_model_map = parse_model_map(path) if (path := os.environ.get("MODEL_MAP")) else {}
MODEL_MAP: ContextVar[ModelMap] = ContextVar('MODEL_MAP', default=_default_model_map)
MODEL: ContextVar[str] = ContextVar('MODEL', default=os.environ.get("MODEL") or "gpt-5.6-sol")
SMALLMODEL: ContextVar[str] = ContextVar('SMALLMODEL', default=os.environ.get("SMALLMODEL") or "gpt-5.6-sol")

# Logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOGS_DIR = Path(os.getenv("LOGS_DIR", CRSROOT / ".." / "logs"))
os.makedirs(LOGS_DIR, exist_ok=True)

# add the running agent, running_tool_call to each log record
def log_context() -> dict[str, Any]:
    return {
        "running_agent": agent.id if (agent := running_agent.get()) else None,
        "running_tool_call": running_tool_call.get(),
        "cur_job_id": cur_job_id.get()
    }

# output text logs to stderr and JSON logs to a file
log_file = LOGS_DIR / datetime.now().strftime("crs_%Y-%m-%d_%H_%M_%S_%f")
crs_rust.logger.configure(
    level=LOG_LEVEL,
    path=log_file,
    context_fn=log_context,
)

# standard logging handler to intercept messages and forward to logger
class InterceptHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        level = record.levelno

        # Find caller from where originated the logged message.
        frame, depth = inspect.currentframe(), 0
        while frame and (depth == 0 or frame.f_code.co_filename == logging.__file__):
            frame = frame.f_back
            depth += 1

        crs_rust.logger.forward_log(level, record.getMessage(), depth=depth, exception=record.exc_info)

# clear pre-existing handlers from all loggers
for logger_name in logging.root.manager.loggerDict:
    logging.getLogger(logger_name).handlers.clear()

# set up standard logging to only use our InterceptHandler
logging.basicConfig(handlers=[InterceptHandler()], level=LOG_LEVEL, force=True)

# attach intercept handler to any non-propagating loggers (they won't reach our handler otherwise)
for logger_name in logging.root.manager.loggerDict:
    logger = logging.getLogger(logger_name)
    if not logger.propagate:
        logger.handlers = [InterceptHandler()]
