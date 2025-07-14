import asyncio
import pytest
import random

from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from pydantic import TypeAdapter
from typing import Any, Optional
from uuid import uuid4, UUID

from crs import config
from crs.app import app
from crs.app.models import SubmissionStatus
from crs.app.app import CRS, WorkType, TaskData, ProcessFuzzCrashData, BundleData, POVData, VulnData, PatchData, DelayPatchData
from crs.common.aio import Path
from crs.common.types import Ok, Err, CRSError, PatchRes, POVRunData, Result
from crs.task_server.models import Task

import tempfile

TASKS_DIR = config.CRSROOT / ".." / "tests" / "app" / "tasks"
POVS_DIR = config.CRSROOT / ".." / "tests" / "modules" / "data" / "povs"

def mutate(input: bytes):
    split = random.randint(0, len(input)-1)
    return input[:split] + random.randbytes(1) + input[split+1:]

@pytest.mark.slow
async def test_triage(best_models: None):
    random.seed(0x1333337)
    project_name = "nginx-asc"
    with tempfile.TemporaryDirectory() as td:
        async def mock(*args: Any, **kwargs: Any):
            return Ok(None)
        CRS.launch_fuzzers = mock

        crs = CRS()
        td = Path(td)
        crs.counterdb._db_path = str(td / "counters.sqlite3") # pyright: ignore
        crs.productsdb._db_path = str(td / "products.sqlite3") # pyright: ignore
        crs.workdb._db_path = str(td / "work.sqlite3") # pyright: ignore
        crs.taskdb._db_path = str(td / "tasks.sqlite3") # pyright: ignore


        task_path = TASKS_DIR / project_name / "full.json"
        task = TypeAdapter(Task).validate_json(await task_path.read_bytes())
        task_id = task.tasks[0].task_id

        povs_dir = POVS_DIR / project_name
        orig_povs: list[tuple[int, str]] = []
        mutated_povs: list[tuple[int, str]] = []
        NUM_MUTANTS = 2
        async with povs_dir.glob("pov_*_*") as pov_it:
            async for path in pov_it:
                if not await path.is_file():
                    continue
                _, _, harness_num = path.name.split("_")
                dst = td / path.name
                _ = await dst.write_bytes(await path.read_bytes())
                orig_povs.append((int(harness_num), str(await dst.absolute())))

                for i in range(NUM_MUTANTS):
                    dst = td / (path.name + f".mutated.{i}")
                    _ = await dst.write_bytes(mutate(await path.read_bytes()))
                    mutated_povs.append((int(harness_num), str(await dst.absolute())))

        async with asyncio.TaskGroup() as tg:
            workdb_loop = tg.create_task(crs.workdb.loop())
            try:
                async def wait_for_jobs_done(worktype: WorkType):
                    while True:
                        await asyncio.sleep(1)
                        tasks = [t for t in crs.workdb.running_tasks[task_id] if worktype.name in t.get_name()]
                        if len(tasks) == 0:
                            break

                await crs.taskdb.put_tasks(task)
                task = (await crs.task_from_id(task_id)).unwrap()

                await crs.workdb.submit_job(
                    task_id,
                    WorkType.LAUNCH_BGWORKERS,
                    TaskData(task_id=task_id),
                    task.deadline_datetime
                )
                await crs.wait_for_bgworker(task)

                # reset all the crash buckets
                harnesses = (await task.project.init_harness_info()).unwrap()
                for harness in harnesses:
                    cm = await crs.bgworkers[task].fuzzer.get_corpus_manager(harness)
                    cm.crash_buckets = {}

                for harness_num, filename in orig_povs:
                    await crs.workdb.submit_job(
                        task_id,
                        WorkType.TRIAGE_FUZZ_CRASH,
                        ProcessFuzzCrashData(task_id=task_id, harness_num=harness_num, filename=filename),
                        task.deadline_datetime
                    )

                await wait_for_jobs_done(WorkType.TRIAGE_FUZZ_CRASH)

                triaged_povs = await crs.productsdb.get_povs_for_task(task_id)
                assert len(triaged_povs) == len(orig_povs)

                await wait_for_jobs_done(WorkType.TRIAGE_POV)

                vulns = await crs.productsdb.get_vulns_for_task(task_id)

                # TODO: can we make sure this holds? currently base64_decode is deduping
                # assert len(vulns) == len(povs)

                for harness_num, filename in mutated_povs:
                    await crs.workdb.submit_job(
                        task_id,
                        WorkType.TRIAGE_FUZZ_CRASH,
                        ProcessFuzzCrashData(task_id=task_id, harness_num=harness_num, filename=filename),
                        task.deadline_datetime
                    )
                await wait_for_jobs_done(WorkType.TRIAGE_FUZZ_CRASH)

                triaged_povs = await crs.productsdb.get_povs_for_task(task_id)
                assert len(triaged_povs) >= 2*len(orig_povs)

                print("waiting for triage to finish")
                await wait_for_jobs_done(WorkType.TRIAGE_POV)

                vulns = await crs.productsdb.get_vulns_for_task(task_id)
                print(f"num vulns: {len(vulns)}")
                for vuln_id, vuln in vulns.items():
                    print(vuln.format())
                    print("povs:", len(await crs.productsdb.get_povs_for_vuln(vuln_id)))
                    print('-'*80)
                assert len(vulns) <= len(orig_povs)

                await wait_for_jobs_done(WorkType.BUNDLE_POV)
                await wait_for_jobs_done(WorkType.PATCH_VULN)
                await wait_for_jobs_done(WorkType.BUNDLE_PATCH)

                bundles = [await crs.productsdb.get_or_create_bundle(task_id, vuln_id) for vuln_id in vulns]
                assert len(bundles) <= len(orig_povs)
                assert all(b.pov_id is not None for b in bundles)
                assert len([b for b in bundles if b.patch_id is not None]) >= len(bundles) // 2

            finally:
                _ = workdb_loop.cancel()


async def test_patch(monkeypatch):
    @dataclass
    class MockProject():
        name = "test project"
    @dataclass
    class MockTask():
        project: MockProject
        task_id: UUID
        deadline_datetime = datetime.now(timezone.utc) + timedelta(minutes=30, seconds=2)
    mock_task = MockTask(project=MockProject(), task_id = uuid4())

    @dataclass
    class MockVuln():
        description: str

    @dataclass
    class MockPOV():
        task_uuid = mock_task.task_id
        project_name = "test"
        id: int
        vuln_id: int

    @dataclass
    class MockArtifact():
        id: int

        @property
        def build_tar_path(self):
            return "test"

    @dataclass
    class MockPatch():
        task_uuid = mock_task.task_id
        project_name = "test"
        id: int
        vuln_id: int

        @property
        def artifacts(self):
            return [MockArtifact(id=self.id)]

    @dataclass
    class MockBundle():
        task_uuid = mock_task.task_id
        id: int
        vuln_id: int
        patch_id: Optional[int]
        pov_id: Optional[int]
        sarif_id = None

    @dataclass
    class MockSubmission():
        status: SubmissionStatus

        def id(self):
            return 1

    @dataclass
    class MockSubmitter():
        povs: list[int] = field(default_factory=list)
        patches: list[int] = field(default_factory=list)
        async def submit_pov(self, task, pov_id: int, pov):
            self.povs.append(pov_id)
        async def submit_patch(self, task, pov_id: int, pov):
            self.patches.append(pov_id)
        async def ping(self):
            return True
        async def poll_patch(*args):
            return "accepted"
        async def poll_pov(*args):
            return "accepted"
        async def submit_bundle(*args):
            return MockSubmission(status="accepted")

    @dataclass
    class MockProducts():
        povs: list[MockPOV]
        patches: list[MockPatch]
        # patchid, povid, patched bool
        patch_results: list[tuple[int, int, bool]] = field(default_factory=list)
        bundles: list[MockBundle] = field(default_factory=list)

        async def get_pov(self, pov_id: int):
            for pov in self.povs:
                if pov.id == pov_id:
                    return pov
        async def get_patch(self, patch_id: int):
            for patch in self.patches:
                if patch.id == patch_id:
                    return patch
        async def get_patches_for_task(self, task_id):
            return {i:patch for i, patch in enumerate(self.patches)}

        async def get_povs_for_task(self, task_id):
            return {i:pov for i, pov in enumerate(self.povs)}

        async def get_patch_results(self, task_id, vuln_id: int):
            return [x for x in self.patch_results if x[0] == vuln_id and x[1] == vuln_id]

        async def get_vuln(self, vuln_id: int):
            return (mock_task.task_id, "vuln", MockVuln(description=f"vuln for {vuln_id}"))

        async def get_submittable_patch_ids_for_vuln(self, vuln_id: int):
            return [patch.id for patch in self.patches if patch.vuln_id == vuln_id]

        async def get_submittable_pov_ids_for_vuln(self, vuln_id: int):
            return [pov.id for pov in self.povs if pov.vuln_id == vuln_id]

        async def get_povs_for_vuln(self, vuln_id: int):
            return [x for x in self.povs if x.vuln_id == vuln_id]

        async def add_patch_results(self, task_id, results: list[tuple[int, int, bool]]):
            self.patch_results += results

        async def get_or_create_bundle(self, task_id, vuln_id: int):
            for bundle in self.bundles:
                if bundle.vuln_id == vuln_id:
                    return bundle
            #patch_id = vuln_id if any(patch.vuln_id == vuln_id for patch in self.patches) else None
            #pov_id = vuln_id if any(pov.vuln_id == vuln_id for pov in self.povs) else None
            bundle = MockBundle(id=len(self.bundles), vuln_id=vuln_id, patch_id=None, pov_id=None)
            self.bundles.append(bundle)
            return bundle

        async def get_bundle_submissions(self, bundle_id: int):
            bundle = self.bundles[bundle_id]
            resp = [None, None, None, None]
            return resp

        async def update_bundle(self, bundle):
            self.bundles[bundle.id] = bundle

    submitter = MockSubmitter()
    povs = [ MockPOV(id=i, vuln_id=i) for i in range(5) ]
    patches = [ MockPatch(id=i, vuln_id=i) for i in range(25) ]
    products = MockProducts(povs=povs, patches=patches)

    async def patch_vuln(self, data):
        print("patching", data)

    async def task_from_id(uuid: UUID):
        return Ok(mock_task)

    async def test_povs_on_patches(task, tests: list[tuple[PatchRes, list[POVRunData]]]) -> Result[list[list[bool]]]:
        return Ok([
            [pov.vuln_id == patch.vuln_id for pov in povs] for patch, povs in tests
        ])

    monkeypatch.setattr(app, "test_povs_on_patches", test_povs_on_patches)
    monkeypatch.setattr(CRS, "patch_vuln", patch_vuln)

    random.seed(0x1333337)
    with tempfile.TemporaryDirectory() as td:
        crs = CRS()
        crs.task_from_id = task_from_id
        crs.productsdb = products
        crs.submitter = submitter

        td = Path(td)
        crs.counterdb._db_path = str(td / "counters.sqlite3") # pyright: ignore
        crs.workdb._db_path = str(td / "work.sqlite3") # pyright: ignore
        crs.taskdb._db_path = str(td / "tasks.sqlite3") # pyright: ignore

        async with asyncio.TaskGroup() as tg:
            workdb_loop = tg.create_task(crs.workdb.loop())
            try:
                # add povs
                for pov in povs:
                    assert( (await crs.bundle_pov(POVData(pov_id=pov.id))).is_ok() )

                # add patches
                for patch in patches:
                    verified = any(pov.vuln_id == patch.vuln_id for pov in povs)
                    if verified:
                        _ = await crs.workdb.submit_job(mock_task.task_id, WorkType.BUNDLE_PATCH, PatchData(patch_id=patch.id, pov_verified=verified), mock_task.deadline_datetime)
                    else:
                        _ = await crs.workdb.submit_job(mock_task.task_id, WorkType.BUNDLE_PATCH_NO_POV, DelayPatchData(patch_id=patch.id, deadline=mock_task.deadline_datetime), mock_task.deadline_datetime)

                await asyncio.sleep(5)

            finally:
                _ = workdb_loop.cancel()

    print(f"povs = {len(submitter.povs)}   patches = {len(submitter.patches)}")
    assert len(submitter.povs) == len(povs)
    assert len(submitter.patches) == 3 * len(povs)