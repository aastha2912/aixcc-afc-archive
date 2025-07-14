import argparse
import asyncio
import itertools
import json
import time

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Type, Tuple

import __init__
from crs import config
from crs.common.utils import tool_wrap
from crs.modules.testing import TestProject
from crs.agents.editable import AddDebugPrintsAgent, CRSEditable

from loguru import logger

PROJECTS_DIR = config.CRSROOT / '..' / 'projects'
PROJECT_NAMES = [dir.name for dir in PROJECTS_DIR.iterdir()]

calls: list[dict[str, Any]] = json.load((Path(__file__).resolve().parent / "debug_pov_calls.json").open())

class Base(AddDebugPrintsAgent):
    @property
    @lru_cache
    def tools(self):
        return {k:v for k,v in super().tools.items() if k not in {"apply_patch", "rewrite_definition"}}

class WithApplyPatch(Base):
    @property
    @lru_cache
    def tools(self):
        return super().tools | {"apply_patch": tool_wrap(self.crs.project.editor.apply_patch)}

class WithRewriteDefinition(Base):
    @property
    @lru_cache
    def tools(self):
        return super().tools | {"rewrite_definition": tool_wrap(self.crs.rewrite_definition)}

@dataclass
class Context:
    cls: Type[Base]
    runs: int = 0
    successes: int = 0
    cost: float = 0
    time: float = 0

    async def _test(self, call: dict[str, Any]) -> Tuple[bool, bool, float, float]:
        projects = await TestProject.from_dir(PROJECTS_DIR / call["project"], None)
        task = (await projects.tasks()).unwrap()[0]
        crs = CRSEditable.from_task(task)
        try:
            args = json.loads(call["args"])
            agent = self.cls(crs, **args)
        except:
            logger.warning(f"Couldn't instantiate cls: {self.cls.__name__}")
            return False, False, 0, 0
        start = time.time()
        _ = await agent.run()
        elapsed = time.time() - start
        if (await crs.project.build_all()).is_err():
            logger.info(f"result failed to build with cls: {self.cls.__name__}")
            return True, False, agent.cost, elapsed
        # TODO: actually run a PoV and detect output?
        for patch in crs.project.editor.patches:
            if "CRS_DEBUG" in patch["patch"]:
                logger.info(f"detected CRS_DEBUG from cls: {self.cls.__name__}")
                return True, True, agent.cost, elapsed
        logger.info(f"didn't detect CRS_DEBUG from cls: {self.cls.__name__}")
        return True, False, agent.cost, elapsed

    async def test(self, call: dict[str, Any]):
        ran, success, cost, time = await self._test(call)
        self.runs += int(ran)
        self.successes += int(success)
        self.cost += cost
        self.time += time
        self.log_stats()

    def log_stats(self):
        logger.info(f"{self.cls.__name__}: {self.successes}/{self.runs} | ${self.cost:.3f} | {time.strftime("%H:%M:%S", time.gmtime(self.time))}")

CONCURRENCY = 10
async def run_experiment():
    contexts = [Context(WithApplyPatch), Context(WithRewriteDefinition)]
    queue: asyncio.Queue[Tuple[dict[str, Any], Context]] = asyncio.Queue()
    for call, context in itertools.product(calls, contexts):
        await queue.put((call, context))

    async def worker():
        while queue.qsize() > 0:
            call, context = queue.get_nowait()
            await context.test(call)
    _ = await asyncio.gather(*[worker() for _ in range(CONCURRENCY)])

async def main():
    parser = argparse.ArgumentParser(description="Code editing experiments")
    _ = parser.add_argument("--model", type=str, default="gpt-4o-2024-08-06", help="The model to use")
    args = parser.parse_args()
    config.MODEL = args.model
    await run_experiment()

if __name__ == "__main__":
    asyncio.run(main())