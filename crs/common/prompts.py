from pathlib import Path
from typing import Any, Optional, Self
import copy

from pydantic import BaseModel, ConfigDict, Field
import jinja2
import yaml

from crs.common.core import trim_tool_output

env = jinja2.Environment()
env.filters["trim_tool_output"] = trim_tool_output

### raw models

class ToolPrompt(BaseModel):
    summary: str
    params: dict[str, str] = Field(default_factory=dict)
    returns: Optional[str] = Field(default=None)

class AgentPrompts(BaseModel):
    system: str
    user: str
    tools: dict[str, ToolPrompt] = Field(default_factory=dict)
    custom: dict[str, str] = Field(default_factory=dict)

    def compile(self) -> "TemplateAgent":
        return TemplateAgent(
            system=env.from_string(self.system),
            user=env.from_string(self.user),
            tools=self.tools,
            custom={
                key: env.from_string(value)
                for key, value in self.custom.items()
            },
        )

class PromptMapping(BaseModel):
    agents: dict[str, AgentPrompts]
    tools: dict[str, ToolPrompt] = Field(default_factory=dict)
    custom: dict[str, str] = Field(default_factory=dict)

    def compile(self) -> "TemplateMapping":
        agents = {name: agent.compile()
                  for name, agent in self.agents.items()}
        custom = {key: env.from_string(value)
                  for key, value in self.custom.items()}
        return TemplateMapping(
            agents=agents,
            tools=self.tools,
            custom=custom,
        )

### bound to env

class BoundCustom(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    custom: dict[str, jinja2.Template]
    kwargs: dict[str, Any]

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            return super().__getattribute__(name)
        try:
            template = self.custom[name]
        except KeyError:
            raise AttributeError(name)
        try:
            return template.render(custom=self, **self.kwargs)
        except Exception as e:
            raise Exception(f"Template Error: {e!r} from custom.{name}")

class BoundAgents(BaseModel):
    mapping: "TemplateMapping"
    kwargs: dict[str, Any]

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            return super().__getattribute__(name)
        return self.mapping.bind(name, kwargs=self.kwargs)

class BoundAgent(BaseModel):
    name: str
    kwargs: dict[str, Any]
    agent: "TemplateAgent"
    custom: BoundCustom

    @property
    def system(self) -> str:
        try:
            return self.agent.system.render(self.kwargs)
        except Exception as e:
            raise Exception(f"Template Error: {e!r} from {self.name}.system")

    @property
    def user(self) -> str:
        try:
            return self.agent.user.render(self.kwargs)
        except Exception as e:
            raise Exception(f"Template Error: {e!r} from {self.name}.user")

    @property
    def tools(self) -> dict[str, ToolPrompt]:
        return self.agent.tools

### unbound, with compiled jinja2.Template objects

class TemplateAgent(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    system: jinja2.Template
    user: jinja2.Template
    tools: dict[str, ToolPrompt]
    custom: dict[str, jinja2.Template]

class TemplateMapping(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    agents: dict[str, TemplateAgent]
    tools: dict[str, ToolPrompt]
    custom: dict[str, jinja2.Template]

    def bind(self, *agent_names: str, kwargs: dict[str, Any]) -> BoundAgent:
        for agent_name in agent_names:
            if (agent := self.agents.get(agent_name)) is not None:
                break
        else:
            raise RuntimeError(f"agent prompts not found: {agent_names}")
        custom = BoundCustom(custom=agent.custom, kwargs=kwargs)
        kwargs["custom"] = custom
        kwargs["agents"] = BoundAgents(mapping=self, kwargs=kwargs)
        return BoundAgent(name=agent_names[0], kwargs=kwargs, agent=agent, custom=custom)

def merge_tools(base: dict[str, ToolPrompt], new: dict[str, ToolPrompt]) -> None:
    for name, tool in new.items():
        base_tool = base.get(name)
        if base_tool is None:
            base[name] = tool
            continue
        base_tool.summary = tool.summary
        base_tool.params.update(tool.params)
        if tool.returns is not None:
            base_tool.returns = tool.returns

class PromptManager:
    raw: dict[str, PromptMapping]
    default: TemplateMapping
    models: dict[str, TemplateMapping]

    def __init__(self, models: dict[str, PromptMapping]):
        self.raw = models.copy()
        default = models.pop("default")
        for agent_name, agent in default.agents.items():
            merge_tools(agent.tools, default.tools)
            agent.custom = {**default.custom, **agent.custom}

        # merge models with default
        for model_name, model in models.items():
            fork = copy.deepcopy(default)
            # merge agents
            for agent_name, agent in model.agents.items():
                base_agent = fork.agents.get(agent_name)
                if base_agent is None:
                    merge_tools(agent.tools, default.tools)
                    fork.agents[agent_name] = agent
                    continue
                merge_tools(base_agent.tools, default.tools)
                merge_tools(base_agent.tools, agent.tools)
            merge_tools(fork.tools, model.tools)
            fork.custom = {**fork.custom, **model.custom}
            for agent in fork.agents.values():
                agent.custom = {**fork.custom, **agent.custom}
            models[model_name] = fork

        self.models = {name: model.compile()
                       for name, model in models.items()}
        self.default = default.compile()

    @classmethod
    def from_path(cls, path: Path) -> Self:
        models: dict[str, PromptMapping] = {}
        for p in path.iterdir():
            if not p.name.endswith(".yaml"):
                continue
            with open(p, "rb") as f:
                raw = yaml.safe_load(f)
            name = p.name.removesuffix(".yaml")
            models[name] = PromptMapping.model_validate(raw)
        return cls(models)

    @classmethod
    def with_agent(cls,
                   agent_name: str,
                   system: str,
                   user: str,
                   custom: Optional[dict[str, str]] = None,
                   tools: Optional[dict[str, ToolPrompt]] = None) -> Self:
        custom = custom or {}
        tools = tools or {}
        obj = cls({
            "default": PromptMapping(agents={
                agent_name: AgentPrompts(system=system, user=user, custom=custom, tools=tools),
            }),
        })
        return obj

    def model(self, name: str) -> TemplateMapping:
        return self.models.get(name, self.default)

prompts_path = Path(__file__).parent.parent.parent / "prompts"
prompt_manager = PromptManager.from_path(prompts_path)
