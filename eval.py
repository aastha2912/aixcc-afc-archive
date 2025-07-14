import argparse
import asyncio
import itertools
import json
import pathlib
import random
import time
import traceback

from collections import defaultdict
from pydantic import TypeAdapter
from typing import Awaitable, Callable, Any, AsyncGenerator, AsyncIterator, Optional, Tuple, TypedDict, List, Dict, NotRequired
from tabulate import tabulate

from crs import config
from crs.common.aio import Path
from crs.common.utils import gather_dict, LimitedTaskGroup
from crs.common.types import Ok, POVRunData, DecodedPOV, AnalyzedVuln
from crs.common.prompts import PromptManager
from crs.modules.project import SANITIZERS, ENGINES
from crs.modules.testing import TestProject
from crs.agents.agent import Agent
from crs.agents.agent_meta import running_agent
from crs.agents.pov_producer import CRSPovProducer, POVProducerResult
from crs.agents.diff_analyzer import CRSDiff
from crs.agents.produce_patch import CRSPatcher, PatchResult

from crs_rust import logger

PROJECTS_DIR = config.CRSROOT / '..' / 'projects'
PROJECTS = [dir.name for dir in pathlib.Path(PROJECTS_DIR).iterdir()]

CONFIG_DIR = config.CRSROOT / '..' / "configs"
MODEL_MAPS = [ f.name for f in pathlib.Path(CONFIG_DIR).glob("*.toml") ]
NON_DEFAULT_MODEL_MAPS = [ "models-none.toml", "models-best-no-azure.toml", "models-round-3.toml" ]
DEFAULT_MODEL_MAPS = [ m for m in MODEL_MAPS if m not in NON_DEFAULT_MODEL_MAPS ]
VULN_COMMITS_FILE = "new_vuln_commits_250523.json"
DEFAULT_MODEL_MAP_CONCURRENCY = 6

MAX_NON_VULN_COMMITS = 32

MAX_CONCURRENT_EVALS_PER_MODEL = 6
EVAL_TIMEOUT = 5*60*60

class Stats(TypedDict):
    value: int
    total: int
    positives: list[int]

class EvalResult(TypedDict):
    eval: str
    project: str
    model: str
    model_map: str
    cost: float
    time: float
    tool_errors: int
    result: Stats | Exception

class PresetConfig(TypedDict):
    eval: str
    models: NotRequired[List[str]]
    projects: List[str]
    model_maps_path_pairs: NotRequired[List[Tuple[str, str]]]


with open(CONFIG_DIR / VULN_COMMITS_FILE, "r", encoding="utf-8") as f:
    _VULN_COMMITS = json.load(f)

VulnCommitMap = dict[str, dict[int, AnalyzedVuln]]
VULN_COMMITS = TypeAdapter(VulnCommitMap).validate_python({
    k: {
        int(inner_k): inner_v
        for inner_k, inner_v in v.items()
    } for k, v in _VULN_COMMITS.items()
})

async def evaluate_pov_producer(project: TestProject, mini: bool):
    # Build Project and init fuzzers, but DON'T start the fuzzers - we're just testing PoVProducer
    _ = (await project.init_harness_info()).unwrap()
    tasks = (await project.tasks()).unwrap()

    commits = VULN_COMMITS[project.name]
    end = len(commits)//2 if mini else len(commits)
    commits = {k: v for k,v in list(commits.items())[:end]}
    # run all pov produer agents
    agents = {
        commit_num: CRSPovProducer.from_task(tasks[commit_num]).produce_pov(desc, 0)
        for commit_num, desc in commits.items()
    }
    results = await gather_dict(agents)
    positives = set(
        commit_num for commit_num, res in results.items()
        if res.unwrap_or(POVProducerResult(success=False)).success
    )

    return Stats(
        value=len(positives),
        total=len(agents),
        positives=list(positives), # type: ignore
    )

async def evaluate_commit_analyzer(project: TestProject, mini: bool):
    commits = VULN_COMMITS[project.name]
    end = len(commits)//2 if mini else len(commits)
    commits = {k: v for k,v in list(commits.items())[:end]}
    tasks = (await project.tasks()).unwrap()

    # run commit agents for each known vuln commit
    agents = {
        commit_num: CRSDiff.from_task(tasks[commit_num]).analyze_diff() for commit_num in commits.keys()
    }
    positives: set[int] = set()
    negatives: set[int] = set()
    for commit_num, result in (await gather_dict(agents)).items():
        match result:
            case Ok(info) if len(info.vuln) > 0:
                positives.add(commit_num)
            case _: 
                negatives.add(commit_num)

    # No vuln? Try again with rawdiff enabled
    agents_rawdiff = {
        commit_num: CRSDiff.from_task(tasks[commit_num]).analyze_diff(rawdiff=True) for commit_num in negatives
    }
    for commit_num, result in (await gather_dict(agents_rawdiff)).items():
        match result:
            case Ok(info) if len(info.vuln) > 0:
                positives.add(commit_num)
            case _: pass

    return Stats(
        value=len(positives),
        total=len(agents),
        positives=list(positives),
    )

async def evaluate_commit_analyzer_false_positives(project: TestProject, mini: bool):
    tasks = (await project.tasks()).unwrap()
    non_vuln = list(set(range(len(tasks))) - VULN_COMMITS[project.name].keys())
    total = 4 if mini else 16
    chosen = random.sample(non_vuln, min(total, len(non_vuln)))

    agents = {
        num: CRSDiff.from_task(tasks[num]).analyze_diff() for num in chosen
    }
    false_positives: set[int] = set()
    for commit_num, result in (await gather_dict(agents)).items():
        match result:
            case Ok(info) if len(info.vuln) > 0:
                false_positives.add(commit_num)
            case _: pass
    return Stats(
        value=len(false_positives),
        total=total,
        positives=list(false_positives)
    )

async def evaluate_patcher(project: TestProject, mini: bool):
    harnesses = (await project.init_harness_info()).unwrap()
    tasks = (await project.tasks()).unwrap()

    commits = VULN_COMMITS[project.name]
    end = len(commits)//2 if mini else len(commits)
    commits = {k: v for k,v in list(commits.items())[:end]}
    povs: defaultdict[int, list[DecodedPOV]] = defaultdict(list)
    povs_dir = (config.CRSROOT / "../tests/modules/data/povs/" / project.name)
    if await povs_dir.exists():
        async with povs_dir.iterdir() as pov_it:
            async for path in pov_it:
                commit_num, harness_num = map(int, path.name.split("_")[1:])
                input = await path.read_bytes()
                harness = harnesses[harness_num]
                _ = (await tasks[commit_num].project.build_all()).unwrap()
                crash = (await tasks[commit_num].project.test_pov_contents(harness, input)).unwrap()
                povs[commit_num].append(
                    POVRunData(
                        task_uuid=tasks[commit_num].task_id,
                        project_name=tasks[commit_num].project.name,
                        harness=harness.name,
                        sanitizer=SANITIZERS[0],
                        engine=ENGINES[0],
                        python=None,
                        input=input,
                        output=crash.output,
                        dedup=crash.dedup,
                        stack=crash.stack,
                    ).safe_decode()
                )
    agents = {
        commit_num: CRSPatcher.from_task(tasks[commit_num]).patch_vulnerability(vuln=vuln, povs=povs[commit_num])
        for commit_num, vuln in commits.items()
    }
    results = await gather_dict(agents)
    positives = set(
        commit_num for commit_num, res in results.items()
        if res.unwrap_or(PatchResult(success=False)).success
    )

    return Stats(
        value=len(positives),
        total=len(agents),
        positives=list(positives), # type: ignore
    )

EVALS: dict[str, Callable[[TestProject, bool], Awaitable[Stats]]] = {
    "commit": evaluate_commit_analyzer,
    "commit_false_positive": evaluate_commit_analyzer_false_positives,
    "pov": evaluate_pov_producer,
    "patch": evaluate_patcher,
}

# dummy agent type just to root the agent tree separately for each eval run
class EvalRoot(Agent):
    @classmethod
    def prompt_manager(cls) -> PromptManager:
        return PromptManager.with_agent(
            agent_name="EvalRoot",
            system="{{ agent.eval }}(\"{{ agent.project_name }}\", model=\"{{ agent.model }}\", model_map_name=\"{{ agent.model_map_name }}\",\n\nmodel_map={{ agent.model_map | tojson }})",
            user="This agent should never run. It only serves as the root of the agent tree for this eval.",
        )

    @property
    def model(self):
        return self._model

    def __init__(self, eval: str, project_name: str, model: str, model_map_name: str, model_map: config.ModelMap, *args: Any, **kwargs: Any):
        self.eval = eval
        self.project_name = project_name
        self._model = model
        self.model_map_name = model_map_name
        self.model_map = model_map
        super().__init__(*args, **kwargs)

async def _run_eval(
    eval: str,
    project: TestProject,
    model: str,
    model_map_path: Path,
    mini: bool,
    timeout: float,
):
    start = time.time()
    model_map = config.parse_model_map(model_map_path)
    root = EvalRoot(eval, project.name, model, model_map_path.name, model_map)
    _ = running_agent.set(root)
    _ = config.MODEL.set(model)
    _ = config.MODEL_MAP.set(model_map)

    try:
        async with asyncio.timeout(timeout):
            try:
                res = await EVALS[eval](project, mini)
            except Exception as e:
                traceback.print_exception(e)
                res = e
    except TimeoutError:
        res = Exception("eval timed out")
    printable = json.dumps(res, indent=2) if not isinstance(res, Exception) else repr(res)
    root.append_user_msg(f"Eval completed:\n\n{printable}")
    results = EvalResult(
        eval=eval,
        project=project.name,
        model=model,
        model_map=model_map_path.name,
        tool_errors=root.tool_errors,
        cost=root.cost,
        time=time.time()-start,
        result=res
    )
    if not isinstance(res, Exception):
        logger.info(
            f"Evaluation '{eval}' on project '{project.name}' finished",
            **(dict(results) | dict(res))
        )
    return results

async def run_evals_with_models(
    evals: list[str],
    projects: list[TestProject],
    model: str,
    model_map_path: Path,
    concurrency: int = DEFAULT_MODEL_MAP_CONCURRENCY,
    mini: bool = False,
    timeout: float = EVAL_TIMEOUT,
) -> AsyncGenerator[EvalResult, None]:
    async with LimitedTaskGroup(concurrency) as tg:
        tasks: list[asyncio.Task[EvalResult]] = []
        for eval, project in itertools.product(evals, projects):
            tasks.append(tg.create_task(_run_eval(eval, project, model, model_map_path, mini, timeout)))
        for result in asyncio.as_completed(tasks):
            yield await result

# helper function to fetch the next item from a specific iterator index
async def _fetch_next[T](iter: AsyncIterator[T]) -> Optional[Tuple[T, AsyncIterator[T]]]:
    try:
        return await iter.__anext__(), iter
    except StopAsyncIteration:
        return None

async def merge_async_generators[T](*gens: AsyncGenerator[T, None]):
    # convert each async generator into an async iterator
    iterators = [ag.__aiter__() for ag in gens]

    async with asyncio.TaskGroup() as tg:
        pending = {tg.create_task(_fetch_next(iterators[i])) for i in range(len(iterators))}
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                match task.result():
                    case None: pass # iterator is done
                    case (item, iter): # iterator produced an item
                        pending.add(tg.create_task(_fetch_next(iter))) # reschedule the iterator fetch
                        yield item

async def run_evals(
    evals: list[str],
    project_names: list[str],
    model: str,
    model_maps: list[str],
    concurrency: int = DEFAULT_MODEL_MAP_CONCURRENCY,
    mini: bool = False,
    timeout: float = EVAL_TIMEOUT,
) -> list[EvalResult]:
    results: list[EvalResult] = []
    logger.info(f"Starting evals with evals={evals}, projects={project_names}, model={model}, model_maps={model_maps}")
    results: list[EvalResult] = []

    projects = [await TestProject.from_dir(PROJECTS_DIR / name) for name in project_names]
    generators = [
        run_evals_with_models(
            evals,
            projects,
            model,
            CONFIG_DIR / model_map,
            concurrency=concurrency,
            mini=mini,
            timeout=timeout
        )
        for model_map in model_maps
    ]

    async for result in merge_async_generators(*generators):
        results.append(result)
    return results

async def main():
    parser = argparse.ArgumentParser(description="CRS evaluations")
    _ = parser.add_argument(
        "--evals",
        type=str,
        nargs="*",
        default=list(EVALS.keys()),
        help="The eval(s) to run",
        choices=list(EVALS.keys())
    )
    _ = parser.add_argument(
        "--projects",
        type=str,
        nargs="*",
        default=PROJECTS,
        help="The project(s) to run on",
        choices=PROJECTS
    )
    _ = parser.add_argument(
        "--model",
        type=str,
        default=config.MODEL.get(),
        help=f"The fallback model to use, e.g. {config.MODEL.get()}",
    )
    _ = parser.add_argument(
        "--model-maps",
        type=str,
        nargs="*",
        default=DEFAULT_MODEL_MAPS,
        help=f"The model map(s) to use, e.g. {' '.join(MODEL_MAPS)}",
        choices=MODEL_MAPS
    )
    _ = parser.add_argument(
        "--timeout",
        type=float,
        default=EVAL_TIMEOUT,
        help="Timeout in seconds for each eval"
    )
    _ = parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_MODEL_MAP_CONCURRENCY,
        help="max number of evals to run concurrently per model-map"
    )
    _ = parser.add_argument(
        "--mini",
        action="store_true",
        help="Run mini evals (reduce work done in each eval)"
    )
    _ = parser.add_argument(
        '--table-out',
        type=str,
        metavar='PATH',
        default="eval-results.txt",
        help='Optional path to dump the output table to'
    )

    args = parser.parse_args()

    args_default_dict:Dict[str, Any] = dict()
    for action in parser._actions:
        args_default_dict[action.dest] = action.default

    results = await run_evals(args.evals, args.projects, args.model, args.model_maps, args.concurrency, args.mini, args.timeout)

    headers: list[str] = ["eval", "project", "model", "model_map", "cost", "time", "tool errors", "total", "value", "exception"]
    data: list[list[Any]] = []
    for res in results:
        row: list[Any] = [res["eval"], res["project"], res["model"], res["model_map"], res["cost"], res["time"], res["tool_errors"]]
        match res["result"]:
            case Exception() as e:
                row.extend([None, None, e])
            case _ as s:
                row.extend([s["total"], s["value"], None])
        data.append(row)
    data.sort() # sort results for a nicer table
    table = tabulate(data, headers=headers, tablefmt="grid")
    print(table)

    if args.table_out:
        with open(args.table_out, "w") as f:
            _ = f.write(f"{table}\n")

if __name__ == "__main__":
    asyncio.run(main())
