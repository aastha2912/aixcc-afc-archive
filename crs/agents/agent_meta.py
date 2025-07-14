from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from crs.agents.agent import AgentGeneric

from contextvars import ContextVar
from typing import Any, Optional

running_agent: ContextVar[Optional['AgentGeneric[Any]']] = ContextVar('running_agent', default=None)
running_tool_call: ContextVar[Optional[str]] = ContextVar('running_tool_call', default=None)