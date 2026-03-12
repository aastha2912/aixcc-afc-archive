from collections import defaultdict
from contextlib import contextmanager
from typing import Any, Callable, Mapping, NotRequired, Optional, Unpack, TypedDict, cast

import asyncio
import functools
import orjson
import os
import random
import re

import litellm

from crs import config
from crs.common.types import ModelResponse, Tool, CRSError, Ok, Err, Result, ToolChoice, ReasoningEffort, Prediction
from crs.common.utils import PrioritySemaphore
from crs.config import *

from crs_rust import logger

litellm._logging._disable_debugging() # type: ignore

DEFAULT_CONCURRENCY = 15
CONCURRENCY = {
    "claude-3-5-sonnet": 45, # TODO: re-evaluate if rules change limits here
    "claude-3-7-sonnet": 15, # TODO: re-evaluate if rules change limits here
    "claude-4-sonnet": 80, # TODO: can we increase this further?
    "claude-4-opus": 60, # TODO: can we increase this further?
    "claude-3-haiku": 80,
    "claude-3-5-haiku": 80,

    "gemini/gemini-2.5-pro": 600,

    "o1": 100,
    "o3": 700,
    "o3-mini": 500,
    "o4-mini": 500,
    "gpt-4.1": 500,
    "gpt-4.1-mini": 500,
    "gpt-4.1-nano": 500,
    "gpt-4o": 500,
    "gpt-4o-mini": 500,
    "gpt-5.3-codex": 500,

    # azure limits should be a different bucket
    "azure/o1-2024-12-17": 100,
    "azure/o3": 100,
    "azure/o3-mini-2025-01-31": 500,
    "azure/o4-mini": 500,
    "azure/gpt-4.1-2025-04-14": 500,
    "azure/gpt-4.1-mini-2025-04-14": 500,
    "azure/gpt-4.1-nano-2025-04-14": 500,
    "azure/gpt-4o-2024-08-06": 500,
    "azure/gpt-4o-mini-2024-07-18": 500,
}

DUPE_MODEL_MAP = {
    "claude-3-5-sonnet-20240620": "claude-3-5-sonnet",
    "claude-3-5-sonnet-20241022": "claude-3-5-sonnet",
    "claude-3-7-sonnet-20250219": "claude-3-7-sonnet",
    "claude-sonnet-4-20250514": "claude-4-sonnet",
    "anthropic/claude-sonnet-4-20250514": "claude-4-sonnet",
    "claude-opus-4-20250514": "claude-4-opus",
    "anthropic/claude-opus-4-20250514": "claude-4-opus",
    "claude-3-7-sonnet-20250219-thinking-low": "claude-3-7-sonnet",
    "claude-3-7-sonnet-20250219-thinking-medium": "claude-3-7-sonnet",
    "claude-3-7-sonnet-20250219-thinking-high": "claude-3-7-sonnet",
    "claude-sonnet-4-20250514-thinking-low": "claude-sonnet-4",
    "claude-sonnet-4-20250514-thinking-medium": "claude-sonnet-4",
    "claude-sonnet-4-20250514-thinking-high": "claude-sonnet-4",
    "claude-3-7-thinking-low": "claude-3-7-sonnet",
    "claude-3-7-thinking-medium": "claude-3-7-sonnet",
    "claude-3-7-thinking-high": "claude-3-7-sonnet",
    "claude-sonnet-4-thinking-low": "claude-sonnet-4",
    "claude-sonnet-4-thinking-medium": "claude-sonnet-4",
    "claude-sonnet-4-thinking-high": "claude-sonnet-4",
    "claude-3-haiku-20240307": "claude-3-haiku",
    "claude-3-5-haiku-20241022": "claude-3-5-haiku",

    "o1-2024-12-17": "o1",
    "o3-2025-04-16": "o3",
    "o3-mini-2025-01-31": "o3-mini",
    "o4-mini-2025-04-16": "o4-mini",
    "gpt-4.1-2025-04-14": "gpt-4.1",
    "gpt-4.1-mini-2025-04-14": "gpt-4.1-mini",
    "gpt-4.1-nano-2025-04-14": "gpt-4.1-nano",
    "gpt-4o-2024-05-13": "gpt-4o",
    "gpt-4o-2024-08-06": "gpt-4o",
    "gpt-4o-2024-11-20": "gpt-4o",
    "gpt-4o-mini-2024-07-18": "gpt-4o-mini",
}

CLAUDE_THINKING_SUPPORTED_MODELS = ["claude-sonnet-4", "claude-3-7-sonnet"]

BUDGET_TOKEN_PAIR = {
    "low":1024,
    "medium":4096,
    "high":8192,
}

CODEX_PRICING_FALLBACKS: dict[str, dict[str, float]] = {
    "gpt-5.3-codex": {
        "input_cost_per_token": 1.75e-06,
        "output_cost_per_token": 1.4e-05,
        "cache_read_input_token_cost": 1.75e-07,
    },
}


def is_codex_model(model: str) -> bool:
    model_name = DUPE_MODEL_MAP.get(model, model)
    return "codex" in model_name


def _msg_text_content(msg: dict[str, Any]) -> str:
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if text := item.get("text"):
                    parts.append(str(text))
        return "\n".join(parts)
    return ""


def _responses_input_from_messages(msgs: list[dict[str, Any]]) -> tuple[str | None, list[dict[str, Any]]]:
    instructions_parts: list[str] = []
    input_items: list[dict[str, Any]] = []

    for msg in msgs:
        role = msg.get("role")
        content = _msg_text_content(msg)

        if role == "system":
            if content:
                instructions_parts.append(content)
            continue

        if role == "assistant":
            if content:
                input_items.append({
                    "role": "assistant",
                    "content": [{"type": "input_text", "text": content}],
                })
            for tool_call in msg.get("tool_calls") or []:
                fn = tool_call.get("function") or {}
                input_items.append({
                    "type": "function_call",
                    "call_id": tool_call.get("id"),
                    "name": fn.get("name"),
                    "arguments": fn.get("arguments", "{}"),
                })
            continue

        if role == "tool":
            input_items.append({
                "type": "function_call_output",
                "call_id": msg.get("tool_call_id"),
                "output": content,
            })
            continue

        if role in {"user", "developer"}:
            input_items.append({
                "role": "user",
                "content": [{"type": "input_text", "text": content}],
            })

    instructions = "\n\n".join(part for part in instructions_parts if part) or None
    return instructions, input_items


def _responses_tools(tools: Optional[list[dict[str, Any]]]) -> Optional[list[dict[str, Any]]]:
    if not tools:
        return None
    result: list[dict[str, Any]] = []
    for tool in tools:
        if tool.get("type") != "function":
            continue
        fn = tool.get("function") or {}
        result.append({
            "type": "function",
            "name": fn.get("name"),
            "description": fn.get("description", ""),
            "parameters": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return result or None


def _responses_tool_choice(tool_choice: Optional[ToolChoice]) -> Any:
    if tool_choice is None:
        return None
    if isinstance(tool_choice, str):
        return tool_choice
    if isinstance(tool_choice, dict) and tool_choice.get("type") == "function":
        fn = tool_choice.get("function") or {}
        return {"type": "function", "name": fn.get("name")}
    return tool_choice


def _response_message_content(output: list[dict[str, Any]], fallback_text: str) -> Optional[str]:
    parts: list[str] = []
    for item in output:
        if item.get("type") != "message":
            continue
        for content in item.get("content") or []:
            text = content.get("text") or content.get("content")
            if text:
                parts.append(str(text))
    if parts:
        return "\n".join(parts)
    return fallback_text or None


def _normalize_responses_usage(usage: dict[str, Any]) -> dict[str, Any]:
    input_details = usage.get("input_tokens_details") or {}
    return {
        "prompt_tokens": usage.get("input_tokens", 0),
        "completion_tokens": usage.get("output_tokens", 0),
        "total_tokens": usage.get(
            "total_tokens",
            usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
        ),
        "prompt_tokens_details": {
            "cached_tokens": input_details.get("cached_tokens", 0),
        },
    }


def _model_pricing(model: str) -> dict[str, float]:
    try:
        info = cast(dict[str, Any], litellm.get_model_info(model)) # type: ignore
    except Exception:
        info = {}
    pricing = CODEX_PRICING_FALLBACKS.get(model, {})
    return {
        "input_cost_per_token": float(info.get("input_cost_per_token", pricing.get("input_cost_per_token", 0.0))),
        "output_cost_per_token": float(info.get("output_cost_per_token", pricing.get("output_cost_per_token", 0.0))),
        "cache_read_input_token_cost": float(info.get("cache_read_input_token_cost", pricing.get("cache_read_input_token_cost", 0.0))),
    }


def _responses_cost(model: str, usage: dict[str, Any]) -> float:
    pricing = _model_pricing(model)
    prompt_tokens = int(usage.get("prompt_tokens", 0))
    completion_tokens = int(usage.get("completion_tokens", 0))
    cached_tokens = int((usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0))
    uncached_input_tokens = max(prompt_tokens - cached_tokens, 0)
    return (
        uncached_input_tokens * pricing["input_cost_per_token"]
        + cached_tokens * pricing["cache_read_input_token_cost"]
        + completion_tokens * pricing["output_cost_per_token"]
    )


async def _responses_completion(args: 'CompletionArgs', tools: Optional[list[dict[str, Any]]]) -> dict[str, Any]:
    from openai import AsyncOpenAI

    instructions, input_items = _responses_input_from_messages(args["messages"])
    client = AsyncOpenAI(
        api_key=os.environ.get("OPENAI_API_KEY"),
        base_url=os.environ.get("OPENAI_API_BASE") or None,
    )

    kwargs: dict[str, Any] = {
        "model": args["model"],
        "input": input_items,
        "instructions": instructions,
        "tools": _responses_tools(tools),
        "tool_choice": _responses_tool_choice(args.get("tool_choice")),
        "temperature": args.get("temperature"),
        "max_output_tokens": args.get("max_completion_tokens"),
        "top_logprobs": args.get("top_logprobs"),
    }
    if reasoning_effort := args.get("reasoning_effort"):
        kwargs["reasoning"] = {"effort": reasoning_effort}
    kwargs = {k: v for k, v in kwargs.items() if v is not None}

    res = await client.responses.create(**kwargs)
    data = res.model_dump()
    output = cast(list[dict[str, Any]], data.get("output", []))
    tool_calls = [
        {
            "id": item.get("call_id") or item.get("id") or "",
            "type": "function",
            "function": {
                "name": item.get("name", ""),
                "arguments": item.get("arguments", "{}"),
            },
        }
        for item in output
        if item.get("type") == "function_call"
    ]
    message = {
        "role": "assistant",
        "content": _response_message_content(output, getattr(res, "output_text", "")),
        "tool_calls": tool_calls or None,
    }
    usage = _normalize_responses_usage(cast(dict[str, Any], data.get("usage", {})))
    cost = _responses_cost(args["model"], usage)
    return {
        "choices": [{
            "message": message,
            "finish_reason": "tool_calls" if tool_calls else "stop",
        }],
        "usage": usage,
        "cost": cost,
    }


class _LLMSpendTracker():
    def __init__(self, parent: Optional['_LLMSpendTracker'] = None):
        self._spend = 0
        self._parent = parent

    def add(self, value: float):
        self._spend += value
        if self._parent:
            self._parent.add(value)

    def spend(self):
        return self._spend

    @contextmanager
    @staticmethod
    def new():
        res = _LLMSpendTracker(llm_spend_tracker.get())
        token = llm_spend_tracker.set(res)
        try:
            yield res
        finally:
            llm_spend_tracker.reset(token)

LLMSpendTracker = _LLMSpendTracker.new
root_tracker = _LLMSpendTracker(None)
llm_spend_tracker: ContextVar[_LLMSpendTracker] = ContextVar('llm_spend_tracker', default=root_tracker)

SWAP_MODELS = bool(os.getenv("SWAP_MODELS", False))
MAX_RETRIES = 8
RATE_LIMIT_DELAY = 15
RATE_LIMIT_EXP = 1.5
MAX_RATE_LIMIT_BASE_DELAY = 240 # sleep range will max out in the range [this, this*RATE_LIMIT_EXP]
EXCEPTION_DELAY = 20

# enable litellm open telemetry logging
if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
    litellm.callbacks = ["otel"]

semaphore_value_gauge = metrics.create_gauge("model-semaphore-value")
semaphore_waiters_gauge = metrics.create_gauge("model-semaphore-waiters")

tokens_limit_gauge = metrics.create_gauge("model-tokens-rate-limit")
tokens_remain_gauge = metrics.create_gauge("model-tokens-rate-remain")
requests_limit_gauge = metrics.create_gauge("model-requests-rate-limit")
requests_remain_gauge = metrics.create_gauge("model-requests-rate-remain")

cost_counter = metrics.create_counter("model-cost")
tokens_total_counter = metrics.create_counter("model-tokens-count-total")
tokens_input_counter = metrics.create_counter("model-tokens-count-input")
tokens_output_counter = metrics.create_counter("model-tokens-count-output")
tokens_cached_counter = metrics.create_counter("model-tokens-count-cached")

@functools.lru_cache(maxsize=10_000) # noqa: CRS102; called from thread
def split_by_tokens(model: str, text: str) -> list[str]:
    """
    split the input text according to the tokenizer
    """
    return [litellm.decode(model, [tok]) for tok in litellm.encode(model, text)] # type: ignore

_func_cache: dict[tuple[str, str, str], dict[str, Any]] = {}

def replace_in_dict(data: Any, old: str, new: str) -> Any:
    """
    Find all str values inside the dictionary and apply replace(old, new) to them.
    """
    if isinstance(data, dict):
        return {k: replace_in_dict(v, old, new) for k, v in data.items()}  # type: ignore
    elif isinstance(data, str):
        return data.replace(old, new)
    else:
        return data
    
def function_parts_to_dict(fname: str, fn: Callable[[Any], Any]) -> dict[str, Any]:
    key = (fname, fn.__name__, fn.__doc__ or "")
    if (value := _func_cache.get(key)) is None:
        fdict: dict[str, Any] = litellm.utils.function_to_dict(fn) # type: ignore
        fdict["name"] = fname
        value = {"type": "function", "function": fdict}
        value = replace_in_dict(value, "!!!tab!!!", "    ")
        _func_cache[key] = value
    return value

def convert_tools(tools: Mapping[str, Tool]) -> Optional[list[dict[str, Any]]]:
    result: list[dict[str, Any]] = []
    for fname, fn in tools.items():
        result.append(function_parts_to_dict(fname, fn))
    return result or None

class CompletionArgs(TypedDict):
    model: str
    n: NotRequired[Optional[int]]
    messages: list[dict[str, Any]]
    tools: NotRequired[Optional[list[dict[str, Any]]]]
    tool_choice: NotRequired[Optional[ToolChoice]]
    temperature: NotRequired[float]
    mock_response: NotRequired[Optional[dict[str, Any]]]
    use_caching: NotRequired[bool]
    prediction: NotRequired[Optional[Prediction]]
    logprobs: NotRequired[Optional[bool]]
    top_logprobs: NotRequired[Optional[int]]
    max_completion_tokens: NotRequired[Optional[int]]
    logit_bias: NotRequired[Optional[dict[int, float]]]
    reasoning_effort: NotRequired[Optional[ReasoningEffort]]

def apply_cache_annotation(msg: dict[str, Any]):
    if msg.get("role") in {"user", "system"} and msg.get("content"):
        if isinstance(msg["content"], str):
            msg["content"] = [{"type": "text", "text": msg["content"], "cache_control": {"type": "ephemeral"}}]
        else:
            msg["content"][0]["cache_control"] = {"type": "ephemeral"}
    elif msg.get("role") == "tool":
        msg["cache_control"] = {"type": "ephemeral"}
    else:
        logger.warning(f"Unknown msg role '{msg.get("role")}', cannot apply cache annotation")

def apply_cache_annotations(msgs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    res = [msg.copy() for msg in msgs]
    cacheable_msgs: list[dict[str, Any]] = []
    prev, count = None, 0
    for msg in res[::-1]:
        # always try to cache system prompt. Note: this include tools
        if msg.get("role") == "system":
            cacheable_msgs.append(msg)
        if prev is None or (count < 2 and prev.get("role") == "assistant" and msg.get("role") in {"user", "tool"}):
            count += 1
            cacheable_msgs.append(msg)
        prev = msg
    assert len(cacheable_msgs) <= 3
    for msg in cacheable_msgs:
        apply_cache_annotation(msg)
    return res

async def do_completion(args: CompletionArgs) -> dict[str, Any]:
    msgs = args["messages"]
    model = args["model"]
    use_caching = args.get("use_caching", True)
    if "use_caching" in args:
        del args["use_caching"]
    tools: Optional[list[dict[str, Any]]] = args.get("tools")

    if is_codex_model(model):
        completion = await _responses_completion(args, tools)
        usage = completion["usage"]
        llm_spend_tracker.get().add(completion["cost"])
        try:
            model_attrs: dict[str, Any] = {
                "model": model,
                "model_dupe": DUPE_MODEL_MAP.get(model, ""),
                "provider": "openai",
            }

            from crs.agents.agent_meta import running_agent
            from crs.common import workdb_meta
            agent = running_agent.get()
            worktype = workdb_meta.cur_job_worktype.get()
            worktype = getattr(worktype, "name", str(worktype))
            task_attrs: dict[str, Any] = {
                "task": str(task) if (task := workdb_meta.cur_job_task.get()) else "none",
                "worktype": worktype,
                "agent": agent.__class__.__name__ if agent else "none",
            }

            cost_counter.add(completion["cost"], task_attrs)
            tokens_total_counter.add(usage["total_tokens"], task_attrs)
            tokens_input_counter.add(usage["prompt_tokens"], task_attrs)
            tokens_output_counter.add(usage["completion_tokens"], task_attrs)
            tokens_cached_counter.add(usage["prompt_tokens_details"]["cached_tokens"], task_attrs)

            cost_counter.add(completion["cost"], model_attrs)
            tokens_total_counter.add(usage["total_tokens"], model_attrs)
            tokens_input_counter.add(usage["prompt_tokens"], model_attrs)
            tokens_output_counter.add(usage["completion_tokens"], model_attrs)
            tokens_cached_counter.add(usage["prompt_tokens_details"]["cached_tokens"], model_attrs)
        except Exception as e:
            logger.exception("Exception while reporting Codex metrics", exception=e)
        return completion

    # hack for anthropic API being annoying
    if not tools and model.startswith("claude"):
        if any(("tool_calls" in msg or "tool_call_id" in msg) for msg in msgs):
            tools = [{'type': 'function',
                'function': {'name': 'do_not_use_tools',
                'description': 'Tools are no longer available. Do not use any tools.',
                'parameters': {'type': 'object', 'properties': {}}}}
            ]
    if use_caching and litellm.utils.supports_prompt_caching(model):
        args["messages"] = apply_cache_annotations(args["messages"])
    kwargs: dict[str, Any] = {
        **args,
        "tools": tools or None,
        "base_url": os.environ.get("AIXCC_LITELLM_HOSTNAME")
    }

    if DUPE_MODEL_MAP.get(kwargs["model"], kwargs["model"]) in CLAUDE_THINKING_SUPPORTED_MODELS:
        kwargs["thinking"] = {"type": "disabled"}
        if "thinking" in kwargs["model"]:
            kwargs["temperature"] = 1
            kwargs["model"] = kwargs["model"].replace("-thinking","")
            kwargs["model"] = kwargs["model"].replace(f"-{kwargs["reasoning_effort"]}","")
            kwargs["thinking"] = {"type": "enabled", "budget_tokens": BUDGET_TOKEN_PAIR[kwargs["reasoning_effort"]]}
            kwargs["max_tokens"] = BUDGET_TOKEN_PAIR[kwargs["reasoning_effort"]] + 4096
            if kwargs['messages'][-1]['role'] != "user":
                kwargs['messages'].append({'role': 'user','content': 'keep going','thinking_blocks': None,'tool_call_id': None,'name': None,'tool_calls': None})
    res = await litellm.acompletion(**kwargs) # type: ignore
    try:
        cost = litellm.completion_cost(res, model=model) # type: ignore
        llm_spend_tracker.get().add(cost)
    except Exception as e:
        cost = 0.0
        logger.exception("Exception while computing completion cost??", exception=e)

    try:
        model_info = litellm.get_model_info(model) # type: ignore
        model_attrs: dict[str, Any] = {
            "model": model,
            "model_dupe": DUPE_MODEL_MAP.get(model, ""),
            "provider": model_info["litellm_provider"],
        }

        from crs.agents.agent_meta import running_agent
        from crs.common import workdb_meta
        agent = running_agent.get()
        worktype = workdb_meta.cur_job_worktype.get()
        worktype = getattr(worktype, "name", str(worktype))
        task_attrs: dict[str, Any] = {
            "task": str(task) if (task := workdb_meta.cur_job_task.get()) else "none",
            "worktype": worktype,
            "agent": agent.__class__.__name__ if agent else "none",
        }

        usage: litellm.Usage = cast(litellm.Usage, res.usage) # type: ignore
        # report tokens and costs per task
        cost_counter.add(cost, task_attrs)
        tokens_total_counter.add(usage.total_tokens, task_attrs)
        tokens_input_counter.add(usage.prompt_tokens, task_attrs)
        tokens_output_counter.add(usage.completion_tokens, task_attrs)
        tokens_cached_counter.add(usage.prompt_tokens_details.cached_tokens or 0, task_attrs) # type: ignore

        # report tokens and costs per model
        cost_counter.add(cost, model_attrs)
        tokens_total_counter.add(usage.total_tokens, model_attrs)
        tokens_input_counter.add(usage.prompt_tokens, model_attrs)
        tokens_output_counter.add(usage.completion_tokens, model_attrs)
        tokens_cached_counter.add(usage.prompt_tokens_details.cached_tokens or 0, model_attrs) # type: ignore

        headers: dict[str, Any] = res._hidden_params["additional_headers"] # type: ignore
        tokens_limit_gauge.set(int(headers.get("x-ratelimit-limit-tokens", 0)), model_attrs)
        tokens_remain_gauge.set(int(headers.get("x-ratelimit-remaining-tokens", 0)), model_attrs)
        requests_limit_gauge.set(int(headers.get("x-ratelimit-limit-requests", 0)), model_attrs)
        requests_remain_gauge.set(int(headers.get("x-ratelimit-remaining-requests", 0)), model_attrs)
    except Exception as e:
        logger.exception("Exception while reporting rate metrics", exception=e)

    return res.model_dump() | {"cost": cost} # type: ignore

class Retry(Exception):
    pass

TOOL_NAME_RE = re.compile("^[a-zA-Z0-9_-]+$")
async def sanity_check_results(res: ModelResponse):
    """
    Check if the results are crappy and we should just try again
    """
    if tool_calls := res.choices[0].message.tool_calls:
        for tool_call in tool_calls:
            fname = tool_call.function.name
            if not TOOL_NAME_RE.match(fname):
                raise Retry("LLM tried to give us a bad tool name!", fname)
            try:
                await asyncio.to_thread(orjson.loads, tool_call.function.arguments)
            except orjson.JSONDecodeError:
                raise Retry("LLM tried to give us a bad tool args!", fname)

semaphores: defaultdict[str, PrioritySemaphore] = defaultdict(
    lambda: PrioritySemaphore(DEFAULT_CONCURRENCY),
    { k: PrioritySemaphore(v) for k,v in CONCURRENCY.items() }
)

class ContextWindowExceeded(CRSError):
    def __init__(self):
        super().__init__("context window exceeded")

class UnknownCompletionError(CRSError):
    pass

class BudgetExceeded(CRSError):
    def __init__(self, budget_usd: float, spend_usd: float):
        super().__init__(f"LLM budget exceeded: spend=${spend_usd:.4f} >= budget=${budget_usd:.4f}")
        self.budget_usd = budget_usd
        self.spend_usd = spend_usd

async def completion(**args: Unpack[CompletionArgs]) -> Result[ModelResponse]:
    retries = 0
    rate_retries = 0
    while True: # noqa: ASYNC913; false positive
        try:
            budget = getattr(config, "LLM_BUDGET_USD", float("inf"))
            spend = llm_spend_tracker.get().spend()
            if spend >= budget:
                return Err(BudgetExceeded(budget, spend))
            completion = await do_completion(args)
            response = ModelResponse(**completion)
            if not config.TELEGRAF:
                logger.info("{model} completion cost: {cost}", model=args["model"], cost=response.cost)
                logger.info("{model} completion usage: {usage}", model=args["model"], usage=response.usage)
            await sanity_check_results(response)
            return Ok(response)
        except Retry:
            logger.exception("immediate retry was requested")
            await asyncio.sleep(0) # asyncio checkpoint
        except litellm.exceptions.RateLimitError:
            # put job back in queue, then sleep
            min_sleep = int(min(RATE_LIMIT_DELAY * RATE_LIMIT_EXP**rate_retries, MAX_RATE_LIMIT_BASE_DELAY))
            sleep_duration = random.randint(min_sleep, int(min_sleep * RATE_LIMIT_EXP))
            rate_retries += 1
            logger.warning(f"Rate limit reached... sleeping for {sleep_duration} seconds before retrying")
            await asyncio.sleep(sleep_duration)
        except litellm.exceptions.ContextWindowExceededError:
            return Err(ContextWindowExceeded())
        except Exception as e:
            logger.exception(f"unknown exception when attempting to call LLM API: {repr(e)}\n")
            if retries >= MAX_RETRIES:
                return Err(UnknownCompletionError(f"reached max retries for completion attempt: {e=}"))
            retries += 1
            await asyncio.sleep(EXCEPTION_DELAY) # noqa: ASYNC120; intended behavior

async def priority_completion(
    priority: float,
    **kwargs: Unpack[CompletionArgs]
) -> Result[ModelResponse]:
    model_name = DUPE_MODEL_MAP.get(kwargs["model"], kwargs["model"])
    if model_name not in CONCURRENCY:
        logger.warning(f"model {model_name} missing from concurrency!")

    sem = semaphores[model_name]
    try:
        semaphore_value_gauge.set(sem.value(), {"model": model_name})
        semaphore_waiters_gauge.set(sem.waiters() + 1, {"model": model_name})
        async with semaphores[model_name].scoped(priority):
            semaphore_value_gauge.set(sem.value(), {"model": model_name})
            return await completion(**kwargs)
    finally:
        semaphore_value_gauge.set(sem.value(), {"model": model_name})
        semaphore_waiters_gauge.set(sem.waiters(), {"model": model_name})
