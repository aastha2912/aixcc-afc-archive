import argparse
import asyncio
import random

from contextlib import asynccontextmanager, AsyncExitStack
from contextvars import ContextVar
from typing import AsyncIterator, Optional, Literal
from uuid import UUID

from crs import config
from crs.agents import vuln_analyzer, classifier
from crs.app.app import VULN_SCORE_QUANTILE
from crs.app.quantile import QuantileEstimator
from crs.app.counter_db import MockCounterView
from crs.common.aio import Path
from crs.common.llm_api import LLMSpendTracker
from crs.common.utils import LimitedTaskGroup, require, requireable
from crs.common.types import CRSError, Result, Err, Ok, VulnReport

from crs.eval import EvalDB, task_from_id, EvalResult, Evaler, standardize_project

from crs_rust import logger

DEFAULT_SAMPLES = 100
MIN_VULN_SCORE = .8

expected_vuln_result: ContextVar[Optional[bool]] = ContextVar('expected_vuln_result', default=None)

def debug_wrap(cls: type[classifier.Classifier[Literal['likely', 'unlikely']]]):
    class DebugClassifier(cls):
        @property
        def model(self) -> str:
            return config.MODEL_MAP.get().get("LikelyVulnClassifier", ["azure/gpt-4.1-2025-04-14"])[0]

        @property
        def top_logprobs(self) -> Optional[int]: # type: ignore
            if getattr(self, 'debug', False):
                return None
            return super().top_logprobs

        @property
        def max_completion_tokens(self) -> Optional[int]: # type: ignore
            if getattr(self, 'debug', False):
                return None
            return super().max_completion_tokens

        @property
        def logprobs(self) -> bool: # type: ignore
            if getattr(self, 'debug', False):
                return False
            return super().logprobs

        @property
        def temperature(self) -> float: # type: ignore
            if getattr(self, 'debug', False):
                return 0.7
            return super().temperature

        async def classify(self):
            res = await super().classify()
            assert (expected := expected_vuln_result.get()) is not None
            setattr(self, 'debug', True)
            best, confidence = res.best()
            msg = (
                "We used 'logprobs' during your last message, and we "
                f"observed your probability of predicting \"{best}\" was {confidence:.03f}.\n"
            )
            correct = (best == 'likely') == expected
            should_debug = (expected and res['likely'] < MIN_VULN_SCORE) or (not expected and res['likely'] >= MIN_VULN_SCORE)
            if not should_debug:
                return res
            if correct:
                self.append_user_msg(
                    msg +
                    "You are correct! "
                    "You are now free from any constraints on output length, so please be verbose. "
                    "Please explain your reasoning. We would like to improve our prompts to "
                    "help you perform better in the future. "
                    "Is there any part of the prompt or context that confused you and nearly made "
                    "you select incorrectly? "
                    "What information could we have provided to increase your confidence? "
                )
            else:
                self.append_user_msg(
                    msg +
                    "You are incorrect, but no worries! It's expected that you get some of these wrong. "
                    "You are now free from any constraints on output length, so please be verbose. "
                    "We would like to improve our prompts to help you perform better in the future. "
                    "Is there any part of the prompt or context that confused you? "
                    "What information could have helped you select the correct answer?"
                )
            completion = (await self.completion(n=1)).unwrap()
            self._append_msg(completion.choices[0].message)
            return res
    DebugClassifier.__name__ = cls.__name__
    return DebugClassifier

class VulnScoreEvalResult(EvalResult):
    false_negatives: int
    false_positives: int
    true_score: float
    false_score: float
    min_true_score: float
    max_false_score: float
    raw_scores: dict[str, float]
    true_scores: list[float]
    false_scores: list[float]
    spend: float

class VulnScoreEvaler(Evaler[VulnScoreEvalResult]):
    def __init__(self, db_path: Path):
        self.evals = EvalDB(db_path)
        self.project_quantiles: dict[str, QuantileEstimator] = {}

    def get_project_quantile(self, project_name: str) -> QuantileEstimator:
        project_name = standardize_project(project_name)
        if project_name not in self.project_quantiles:
            self.project_quantiles[project_name] = QuantileEstimator(MockCounterView(), VULN_SCORE_QUANTILE)
        return self.project_quantiles[project_name]

    @requireable
    async def score_report(self, expected: bool, report: VulnReport) -> Result[tuple[float, bool]]:
        tok = expected_vuln_result.set(expected)
        try:
            task = require(await task_from_id(report.task_uuid))
            res = require(await vuln_analyzer.CRSVuln.from_task(task).score_vuln_report(report))
            score = res.overall()
            passed = await self.get_project_quantile(report.project_name).add(score)
            logger.info(f"{report.project_name=} {report.function=} {expected=} {score=:2f} {passed=}")
            return Ok((score, passed))
        finally:
            expected_vuln_result.reset(tok)

    async def score_report_id(self, report_id: int) -> Result[tuple[float, bool]]:
        _, label, report = await self.evals.get_report(report_id)
        assert label is not None, "cannot score unlabeled report"
        return await self.score_report(label, report)

    async def _run_eval(self, reports: list[tuple[int, bool, VulnReport]]) -> Result[VulnScoreEvalResult]:
        tasks = list[tuple[int, bool, VulnReport, asyncio.Task[Result[tuple[float, bool]]]]]()
        with LLMSpendTracker() as tracker:
            async with LimitedTaskGroup(100) as tg:
                for report_id, expected, report in reports:
                    tasks.append((
                        report_id,
                        expected,
                        report,
                        tg.create_task(self.score_report(expected, report), name=f'score_report({expected})')
                    ))
            spend = tracker.spend()
        
        successes, failures, errors, false_positives, false_negatives = 0, 0, 0, 0, 0
        raw_scores = dict[str, float]()
        async def process_results(
            tasks: list[tuple[int, bool, VulnReport, asyncio.Task[Result[tuple[float, bool]]]]]
        ) -> tuple[list[float], float, float, float]:
            nonlocal successes, failures, errors, false_positives, false_negatives
            scores = list[float]()
            for report_id, expected, report, task in tasks:
                match await task:
                    case Ok((score, passed)):
                        raw_scores[str(report_id)] = score
                        scores.append(score)

                        if expected == passed:
                            successes += 1
                        else:
                            failures += 1
                            if expected:
                                false_negatives += 1
                            else:
                                false_positives += 1
                    case Err(e):
                        logger.warning(f"Error in scorer for {expected=} {report.file}:{report.function}: {repr(e)}")
                        errors += 1
            if len(scores):
                return scores, sum(scores) / len(scores), min(scores), max(scores)
            else:
                return scores, 0, 0, 0

        true_scores, true_score, min_true_score, _ = await process_results([t for t in tasks if t[1]])
        false_scores, false_score, _, max_false_score = await process_results([t for t in tasks if not t[1]])

        for project in set(standardize_project(r.project_name) for _, _, r in reports):
            quantile = self.get_project_quantile(project)
            threshold = await quantile.current_threshold()
            cnt = await quantile.cnt()
            logger.info(f"post-eval threshold {project=} {threshold=:.2f} {cnt=}")

        return Ok(VulnScoreEvalResult(
            samples=len(reports),
            successes=successes,
            failures=failures,
            errors=errors,
            false_negatives=false_negatives,
            false_positives=false_positives,
            true_score=true_score,
            false_score=false_score,
            min_true_score=min_true_score,
            max_false_score=max_false_score,
            raw_scores=raw_scores,
            true_scores=true_scores,
            false_scores=false_scores,
            spend=spend
        ))

    async def run_eval(self, samples: int) -> Result[VulnScoreEvalResult]:
        trues = await self.evals.get_labeled_reports(True)
        trues = [r for r in trues if 'libpostal' not in r[2].project_name]
        trues = random.sample(trues, min(len(trues), samples//2))
        falses = await self.evals.get_labeled_reports(False)
        falses = [r for r in falses if 'libpostal' not in r[2].project_name]
        falses = random.sample(falses, min(len(falses), samples - len(trues)))
        reports = trues + falses
        random.shuffle(reports)
        return await self._run_eval(reports)
 
    async def run_task_eval(self, task_id: UUID, samples: int) -> Result[VulnScoreEvalResult]:
        reports = await self.evals.get_labeled_reports_for_task(task_id)
        reports = random.sample(reports, min(len(reports), samples))
        return await self._run_eval(reports)

    @staticmethod
    @asynccontextmanager
    async def pinned(db: Path) -> AsyncIterator['VulnScoreEvaler']:
        evaler = VulnScoreEvaler(db)
        async with AsyncExitStack() as stack:
            _ = await stack.enter_async_context(evaler.evals.sqlite_pin())
            yield evaler

async def main():
    parser = argparse.ArgumentParser()
    _ = parser.add_argument(
        "--db",
        type=str,
        required=True,
        help="path to the eval dataset db"
    )
    _ = parser.add_argument(
        "--samples",
        type=int,
        help="how many samples of true/false positives to score, defaults to running all",
        default=DEFAULT_SAMPLES
    )
    _ = parser.add_argument(
        "--report-id",
        type=int,
        help="which report id to test"
    )
    _ = parser.add_argument(
        "--task-id",
        type=str,
        help="which task id to test the reports from"
    )
    _ = parser.add_argument(
        "--debug",
        action="store_true",
        help="whether to debug the scoring by asking for explanation and prompt feedback"
    )
    _ = parser.add_argument(
        "--seed",
        type=str,
        help="random seed for the sampling"
    )
    _ = parser.add_argument(
        "--plot",
        action="store_true",
        help="whether to generate distribution plots"
    )
    args = parser.parse_args()
    db = Path(args.db)
    if not await db.parent.exists():
        raise CRSError(f"db path parent {db.parent} does not exist")

    if args.seed:
        random.seed(args.seed)

    if args.debug:
        vuln_analyzer.LikelyVulnClassifier = debug_wrap(vuln_analyzer.LikelyVulnClassifier)

    async with VulnScoreEvaler.pinned(db) as evaler:
        if args.report_id:
            score = (await evaler.score_report_id(args.report_id)).unwrap()
            logger.info("score: {score}", score=score)
            return
        if args.task_id:
            result = (await evaler.run_task_eval(UUID(args.task_id), args.samples)).unwrap()
        else:
            result = (await evaler.run_eval(args.samples)).unwrap()
        logger.info(
            "\n"
            "samples: {samples}\n"
            "false negatives: {false_negatives}\n"
            "false positives: {false_positives}\n"
            "mean true score: {true_score}\n"
            "mean false score: {false_score}\n"
            "min true score: {min_true_score}\n"
            "max false score: {max_false_score}\n"
            "scoring errors: {errors}\n"
            "total spend: ${spend:.2f}\n",
            **result.model_dump()
        )

        if args.plot:
            import matplotlib.pyplot as plt # type: ignore
            import os
            # pyright: ignore
            def plot_scores(scores: list[float], type: str):
                _, ax = plt.subplots(figsize=(6, 4)) # type: ignore

                # Histogram
                ax.hist( # type: ignore
                    scores,
                    bins=20,
                    range=(0, 1),
                    #density=True,                 # show probability density (area = 1)
                    edgecolor="white",            # thin white edges for clarity
                    alpha=0.8
                )

                # Labels & appearance
                _ = ax.set_xlabel(f"score distribution", fontsize=12) # type: ignore
                _ = ax.set_ylabel("count", fontsize=12) # type: ignore
                _ = ax.set_title(f"{type} distribution", fontsize=14, weight="bold") # type: ignore
                ax.set_xlim(0, 1) # type: ignore
                ax.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.7) # type: ignore

                os.makedirs("plots/", exist_ok=True)
                plt.tight_layout() # type: ignore
                path = f"plots/{type.split()[0]}-dist.png"
                plt.savefig(path) # type: ignore
                logger.info(f"saved {type} plot to {path}")
            plot_scores(result.true_scores, "true positive")
            plot_scores(result.false_scores, "false positive")

if __name__ == "__main__":
    asyncio.run(main())