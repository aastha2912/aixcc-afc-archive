import inspect
from abc import abstractmethod
from pydantic import BaseModel, ValidationError

from crs.agents.agent import AgentGeneric
from crs.agents.xml_agent import describe_model, describe_errors
from crs.common.types import Coro, Err, CRSError, Tool, Message, Result, Ok, Callable
from crs.common.utils import cached_property, tool_wrap
from typing import Any, Optional, Mapping, Union, final, get_origin, get_args

TOOL_CHECKED_ATTRIBUTE = "_tool_ready"

def ToolVerifyClass[R: BaseModel](cls: type[R]) -> type[R]:
    _ = describe_model(cls.model_json_schema(), nested_ok=False)

    for field_name, field in cls.model_fields.items():
        if get_origin(field.annotation) is list:
            assert field.is_required(), f"{field_name} is an optional list: not allowed!"
        if get_origin(field.annotation) is Union:
            assert all([get_origin(x) is not list for x in get_args(field.annotation)]), f"{field_name} is an optional list: not allowed!"

    setattr(cls, TOOL_CHECKED_ATTRIBUTE, True)
    return cls

class ToolRequiredAgent[R: BaseModel](AgentGeneric[R]):
    @property
    @abstractmethod
    def return_type(self) -> type[R]:
        pass

    @cached_property
    def _terminate_func(self) -> Callable[..., Coro[Result[None]]]:
        """
        Dynamically create a function whose signature matches the fields of `model_cls`.
        Calling the function will instantiate and return an instance of `model_cls`.
        """

        async def terminate(**kwargs: Any) -> Result[None]:
            try:
                self.result = self.return_type(**kwargs)
                return Ok(None)
            except ValidationError as e:
                return Err(CRSError(describe_errors(e, self.return_type)))
        terminate.__qualname__ = "ToolRequiredAgent.terminate"

        # Build up a list of Parameters, matching the model's fields
        parameters: list[inspect.Parameter] = []
        for field_name, field_info in self.return_type.model_fields.items():
            default = inspect.Parameter.empty if field_info.is_required() else field_info.default

            param = inspect.Parameter(
                name=field_name,
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=default,
                annotation=field_info.annotation,
            )
            parameters.append(param)

        parameters.sort(key=lambda p: p.default is not inspect.Parameter.empty)
        new_signature = inspect.Signature(parameters=parameters, return_annotation=None)
        setattr(terminate, '__signature__', new_signature)
        terminate.__annotations__ = {
            field_name: field_info.annotation
            for field_name, field_info in self.return_type.model_fields.items()
        }

        doc_lines = [
            "Parameters",
            "----------"
        ]
        for field_name, field_info in self.return_type.model_fields.items():
            # Extract a type hint as a string
            field_type = str(field_info.annotation)
            if field_info.is_required():
                doc_lines.append(f"{field_name} : {field_type}")
            else:
                doc_lines.append(f"{field_name} : {field_type}, optional")
            if field_info.description:
                doc_lines.append(f"    {field_info.description}")
            else:
                doc_lines.append(f"    (no description provided)")
        terminate.__doc__ = "\n".join(doc_lines)

        return terminate

    @cached_property
    def _tools(self) -> Mapping[str, Tool]:
        return {}

    @cached_property
    @final
    def tools(self):
        return dict(self._tools.items()) | {"terminate": tool_wrap(self._terminate_func)}

    @property
    def tool_choice(self):
        if "o4" in self.model or "o3" in self.model or "o1" in self.model:
            return "required"
        return "auto"

    def get_result(self, msg: Message):
        if not msg.tool_calls:
            return Message(role="user", content="You must call a tool. When you are finished, use the `terminate` tool.")
        return self.result

    def __init__(self):
        self.result: Optional[R] = None
        assert hasattr(self.return_type, TOOL_CHECKED_ATTRIBUTE), "models passed to ToolResultAgent must be verified!"
        super().__init__()

        # pyright currently doesn't enforce @final with @property
        # https://github.com/microsoft/pyright/issues/9795
        # temporary workaround:
        assert "terminate" in self.tools, "should not override `ToolRequiredAgent.tools` - use _tools instead"
