import asyncio
from litellm import Choices, Message, ModelResponse # pyright: ignore [reportPrivateImportUsage]
import random
import time
import functools
from typing import Any, Mapping, Optional

from crs.agents.agent import Agent
from crs.common.prompts import PromptManager
from crs.common.types import Ok, Err, CRSError, ToolSuccess, AgentAction, Tool
from crs.common.utils import cached_property, tool_wrap

random.seed(0x1337)

MAGIC_NUMBER = random.randint(0, 31)

class NoToolsAgent(Agent):
    @classmethod
    def prompt_manager(cls) -> PromptManager:
        return PromptManager.with_agent(
            agent_name="NoToolsAgent",
            system="_",
            user="What is your name?",
        )

    @cached_property
    def tools(self) -> Mapping[str, Tool]:
        return {}

async def test_no_tools():
    _ = await NoToolsAgent().run()

class Guesser(Agent):
    @classmethod
    def prompt_manager(cls) -> PromptManager:
        return PromptManager.with_agent(
            agent_name="Guesser",
            system="Give it your best shot",
            user="""
            Guess the magic number in a few steps as possible.
            Try to use a smart strategy based on the feedback you receive.
            Don't stop until you guess the right value.
            You must explain your thoughts at each step.
            """,
        )

    async def guess(self, magic_number: int):
        """
        Guess the magic number (something in the range [0, 31]) and receive feedback.

        Parameters
        ----------
        magic_number: int
            Your guess for the magic number.

        Returns
        -------
        str
            Information about your guess
        """
        if magic_number == MAGIC_NUMBER:
            self.success = True
            return Ok("You got it! Great work!")
        elif magic_number > MAGIC_NUMBER:
            return Err(CRSError("Too big."))
        else:
            return Err(CRSError("Too small."))

    async def terminate(self):
        """
        Terminate the conversation. Only call this once you have finished your task.
        """
        return ToolSuccess(result=None, action=AgentAction(stop=True))

    @cached_property
    def tools(self):
        @functools.wraps(self.terminate)
        async def terminate():
            return await self.terminate()

        return {
            "guess": tool_wrap(self.guess),
            "terminate": terminate,
        }

    @property
    def tool_choice(self):
        return "required"

    def __init__(self: 'Guesser'):
        self.success = False
        super().__init__()

async def test_guesser():
    g = Guesser()
    _ = await g.run()
    assert g.success, "Guesser failed"

async def test_serialized_guesser():
    g = Guesser()
    _ = await g.run(max_iters=1)
    serialized = g.serialize()
    g = Guesser.deserialize(serialized)
    _ = await g.run()
    assert g.success, "Deserialized guesser failed"


class Sleeper(Agent):
    @classmethod
    def prompt_manager(cls) -> PromptManager:
        return PromptManager.with_agent(
            agent_name="Sleeper",
            system="Sleep",
            user="test",
        )

    async def sleep(self, time: int):
        """
        Sleep the given number of seconds.

        Parameters
        ----------
        time: int
            how much to sleep
        """
        await asyncio.sleep(time)
        self.count += 1
        return Ok(None)

    async def terminate(self):
        """
        Terminate the conversation. Only call this once you have finished your task.
        """
        return ToolSuccess(result=None, action=AgentAction(stop=True))

    @cached_property
    def tools(self):
        @functools.wraps(self.terminate)
        async def terminate():
            return await self.terminate()

        return {
            "sleep": tool_wrap(self.sleep),
            "terminate": terminate,
        }

    def mock_response(self, msgs: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
        if msgs[-1].get("content") == "test":
            mr = ModelResponse(choices=[
                Choices(finish_reason='stop', message=Message(
                    content='test',
                    tool_calls=[
                        {'function': {'name':'sleep', 'arguments': '{"time": 1}'}}
                        for _ in range(10)
                    ]
                ))
            ])
            return mr.model_dump()
        else:
            mr = ModelResponse(choices=[
                Choices(finish_reason='stop', message=Message(
                    content='test',
                    tool_calls=[
                        {'function': {'name':'terminate', 'arguments': "{}"}},
                    ]
                ))
            ])
            return mr.model_dump()

    def __init__(self: 'Sleeper'):
        self.success = False
        self.count = 0
        super().__init__()


async def test_sleeper():
    g = Sleeper()
    start = time.time()
    _ = await g.run()
    dur = time.time() - start
    assert 1 < dur < 5, "Sleeper too slow"
    assert g.count == 10, "Sleeper failed"
