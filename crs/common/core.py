import sys
import types
from typing import Any, Callable, Coroutine, Dict, List, Literal, NotRequired, Optional, TypedDict, overload

from pydantic import BaseModel, ConfigDict

from result import Ok, Err
from .constants import MAX_TOOL_CALL_RESULT_LENGTH

def synthetic_traceback(level: int=0):
    frame = sys._getframe(level) # type: ignore
    tb = None
    while frame.f_back is not None:
        frame = frame.f_back
        tb = types.TracebackType(tb, frame, frame.f_lasti, frame.f_lineno)
    return tb

@overload
def trim_tool_output(output: str, ratio: float = 1/2) -> str:
    pass
@overload
def trim_tool_output(output: bytes, ratio: float = 1/2) -> bytes:
    pass
def trim_tool_output(output: str | bytes, ratio: float = 1/2):
    max_len = int(MAX_TOOL_CALL_RESULT_LENGTH * ratio)
    if len(output) > max_len:
        # include a good amount at the beginning, and some at the end, trim the middle
        if isinstance(output, str):
            output = output[:max_len * 2 // 3] + "\n[...]\n" + output[-max_len // 3:]
        else:
            output = output[:max_len * 2 // 3] + b"\n[...]\n" + output[-max_len // 3:]
    return output


class ToolCallFunction(BaseModel):
    name: str
    arguments: str
    model_config = ConfigDict(extra="ignore") # Ignore any extra fields in the input dictionary

class ToolCall(BaseModel):
    id: str
    function: ToolCallFunction
    type: Literal["function"]
    model_config = ConfigDict(extra="ignore") # Ignore any extra fields in the input dictionary

class TopLogProbs(BaseModel):
    token: str
    logprob: float
    model_config = ConfigDict(extra="ignore") # Ignore any extra fields in the input dictionary

class LogProbData(BaseModel):
    top_logprobs: list[TopLogProbs]
    token: str
    model_config = ConfigDict(extra="ignore") # Ignore any extra fields in the input dictionary

class LogProbs(BaseModel):
    content: list[LogProbData]
    model_config = ConfigDict(extra="ignore") # Ignore any extra fields in the input dictionary

class Message(BaseModel):
    role: str
    content: Optional[str] = None
    thinking_blocks: Optional[List[Dict[str,Any]]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None
    tool_calls: Optional[List[ToolCall]] = None
    model_config = ConfigDict(extra="ignore") # Ignore any extra fields in the input dictionary

class Choice(BaseModel):
    message: Message
    logprobs: Optional[LogProbs] = None
    finish_reason: Optional[str] = None
    model_config = ConfigDict(extra="ignore") # Ignore any extra fields in the input dictionary

class ModelResponse(BaseModel):
    choices: List[Choice]
    cost: float
    usage: dict[str, Any]

class Function(TypedDict):
    name: str

class ToolChoiceDict(TypedDict):
    type: str
    function: NotRequired[Function]

type ToolChoice = Literal["auto", "required", "none"] | ToolChoiceDict

class Prediction(TypedDict):
    type: Literal["content"]
    content: str

ReasoningEffort = Literal['low', 'medium', 'high']

class AgentResult[T](BaseModel):
    response: Optional[T]
    terminated: bool
    msgs: list[Dict[str, Any]]

# stupid hack uses harnesses bigger than this for special meaning
HARNESS_IGNORED_AT = 4096

class AgentAction(BaseModel):
    stop: bool = False
    # this default of [] is safe: pydantic does a magic deepcopy
    append: List[Message] = []
    rewind: int = 0


class ToolError(BaseModel):
    error: str
    # TODO: add source based on traceback?
    extra: Optional[dict[str, Any]]
    # this default of AgentAction() is safe: pydantic does a magic deepcopy
    action: AgentAction = AgentAction()

    def __init__(self, error: str, extra: Optional[dict[str, Any]] = None, action: Optional[AgentAction] = None):
        super(ToolError, self).__init__(error=error, extra=extra, action=action or AgentAction())

class ToolSuccess[T](BaseModel):
    result: T
    # this default of AgentAction() is safe: pydantic does a magic deepcopy
    action: AgentAction = AgentAction()

    def __init__(self, result: T, action: Optional[AgentAction] = None):
        super(ToolSuccess, self).__init__(result=result, action=action or AgentAction())

# common exception type for all of our handled exceptions
class CRSError(Exception):
    def __init__(self, error: str, extra: Optional[dict[str, Any]] = None, include_traceback: bool = True):
        self.error = error
        self.extra = extra
        if include_traceback:
            self.__traceback__ = synthetic_traceback(level=1)

    def __repr__(self):
        return f'{self.__class__.__name__}({self.error}, extra={self.extra})'

# simplify result bsaed on fixed error type
type Result[T] = Ok[T] | Err[CRSError]

type Coro[R] = Coroutine[Any, Any, R]
type ToolResult[T] = ToolSuccess[T] | ToolError
type ToolT[**P, T] = Callable[P, Coro[ToolResult[T]]]
Tool = ToolT[..., Any]