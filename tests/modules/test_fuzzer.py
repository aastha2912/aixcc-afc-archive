import asyncio
from collections import defaultdict
import contextlib
from dataclasses import dataclass
import pytest
import tempfile
import uuid

from crs.common import constants, docker
from crs.common.aio import Path
from crs.common.types import Ok, Err
from crs.modules import coverage, fuzzing, project
from crs.modules.project import Project, Task


@pytest.mark.slow
async def test_fuzzing(built_project: Project):
    project = built_project.new_fork()
    with tempfile.TemporaryDirectory() as temp_proj_dir:
        orig_data_dir = project.data_dir
        # easy hack to have no caching for fuzzing, but caching for build info
        project.data_dir = Path(temp_proj_dir)
        task = Task(uuid.uuid4(), 0, project, coverage.CoverageAnalyzer(project), {})
        fm = fuzzing.FuzzManager(task)

        # just run one fuzzer in case there are multiple harnesses
        match await project.init_harness_info():
            case Ok(harnesses):
                pass
            case Err(e):
                raise e
        fuzzer = (await fm.get_fuzzers())[constants.DEFAULT_SANITIZER][harnesses[0]]
        assert fuzzer
        project.data_dir = orig_data_dir

        assert len(fuzzer.corpus_manager.seeds) == 0

        sem = asyncio.Semaphore(1)

        try:
            async with asyncio.timeout(10):
                _ = await fuzzer.run_harness_task(sem, False, 2)
        except TimeoutError:
            pass

        seeds_after_unzip = len(fuzzer.corpus_manager.seeds)

        try:
            async with asyncio.timeout(50):
                _ = await fuzzer.run_harness_task(sem, False, 2)
        except TimeoutError:
            pass

        assert len(fuzzer.corpus_manager.seeds) > seeds_after_unzip + 4

@pytest.mark.slow
@pytest.mark.parametrize(
    ["task_harnesses", "machines", "cores", "sanitizers"],
    [
        ([4, 5, 4], 8, 32, 1),
        ([1,2]*11, 6, 32, 1), ([1,2,3]*7, 6, 32, 1),
        ([2], 20, 32, 2), ([3, 10, 1, 2], 10, 1, 3), ([4, 5, 4], 1, 20, 2), ([4, 5, 4], 8, 32, 3), ([4, 15, 4], 8, 32, 3), ([2, 4], 4, 1, 5),
        ([2], 20, 32, 1), ([4], 4, 1, 1), ([3], 10, 1, 1), ([4], 1, 20, 1), ([20], 4, 4, 1), ([100], 8, 32, 1),
        ([2, 4], 20, 32, 1), ([4, 1, 1], 4, 1, 1), ([3, 10, 1, 2], 10, 1, 1), ([4, 4, 4], 1, 20, 1), ([20, 6, 1], 4, 4, 1), ([100, 10, 1], 8, 32, 1),
        ([2,2,2,2,2,2,2,2,2,2], 8, 4, 1), ([2,2,2,2,2,2,2,2,2,2], 8, 1, 1),
    ]
)
async def test_allocations(monkeypatch, task_harnesses: list[int], machines: int, cores: int, sanitizers: int):
    """
    Run "fake" fuzzing to make sure we have equitable fuzzer allocation stuff
    """
    duration = 20
    ticks_per_sec = 5
    monkeypatch.setenv("CRS_FUZZER_COUNT", str(machines))
    monkeypatch.setenv("CRS_FUZZER_CORES", str(cores))

    monkeypatch.setattr(fuzzing, "SINGLE_FUZZER_TIMEOUT", 2)
    monkeypatch.setattr(fuzzing, "FUZZER_GRACE_PERIOD", 1)
    monkeypatch.setattr(fuzzing, "REBALANCE_COOLDOWN", 0.0)
    monkeypatch.setattr(docker, "manager", docker.DockerManager())

    with tempfile.TemporaryDirectory() as tmpdir:
        l = asyncio.Lock()
        machine_workers: dict[str, int] = defaultdict(int)
        machine_used: dict[str, bool] = defaultdict(bool)
        work_completed: dict[str, int] = defaultdict(int)

        class FakeReadable:
            async def readline(self):
                return b""

        class FakeProc:
            def __init__(self, desc, sleep, done_callback=None, outp=None):
                self.desc = desc
                self.sleep = sleep
                self.done_callback = done_callback
                self.returncode = None
                self.outp = outp
                self.stdout = FakeReadable()

            def kill(self):
                pass

            async def wait(self):
                try:
                    #if self.desc:
                    #    print(f"running {self.desc}")
                    if self.returncode is None:
                        await asyncio.sleep(self.sleep)
                    self.returncode = 0
                    #if self.desc:
                    #    print(f"finished {self.desc}")
                    return 0
                finally:
                    if self.done_callback:
                        await self.done_callback()

            async def communicate(self):
                try:
                    #if self.desc:
                    #    print(f"running {self.desc}")
                    if self.returncode is None:
                        await asyncio.sleep(self.sleep)
                    self.returncode = 0
                    #if self.desc:
                    #    print(f"finished {self.desc}")
                    if self.outp is  None:
                        return b"", b""
                    else:
                        return self.outp
                finally:
                    if self.done_callback:
                        await self.done_callback()

        async def fake_exec(self: docker.DockerScope, *args, **kwargs):
            #print("fake exec", self, args, kwargs)
            if "sleep infinity" in " ".join(args):
                cid_idx, = [i+1 for i, arg in enumerate(args) if arg == "--cidfile"]    
                open(args[cid_idx], "w").write("dummy_cid")
                print(f"treating as docker run and sleep; writing to {args[cid_idx]}")
                return FakeProc("docker run bkg", 100)
            elif "docker events" in " ".join(args):
                return FakeProc("docker run bkg", 0, outp=(b"running", b""))
            elif "run_fuzzer" in " ".join(args):
                fargs = ((" ".join(args)).split("run_fuzzer")[1]).split()
                def get_arg(s):
                    return [x.removeprefix(s) for x in fargs if x.startswith(s)][0]
                cores_used = int(get_arg("-jobs="))
                assert cores_used == int(get_arg("-workers="))
                assert cores_used <= self.host.cores, "asked for more cores than exist"

                machine_used[self.host.ip] = True

                fuzzer = fargs[0]
                async with l:
                    machine_workers[self.host.ip] += cores_used
                    assert machine_workers[self.host.ip] <= cores, f"too many cores on machine {self.host.ip}!"
                print(f"launching {fuzzer} with {cores_used} cores on {self.host.ip}")

                async def done_callback():
                    print(f"finished {fuzzer} with {cores_used} cores on {self.host.ip}")
                    work_completed[fuzzer] += cores_used
                    async with l:
                        machine_workers[self.host.ip] -= cores_used

                return FakeProc("fuzz", (1/ticks_per_sec) - 0.005, done_callback=done_callback)
            else:
                return FakeProc(None, 0)

        overwatcher = fuzzing.FuzzOverwatcher(machines=machines, cores=cores)
        monkeypatch.setattr(fuzzing, "fuzzoverwatcher", overwatcher)

        monkeypatch.setattr(docker.DockerScope, "exec", fake_exec)

        @dataclass
        class MockProject:
            data_dir: Path
            name: str
            info: project.ProjectInfo

        @dataclass
        class MockTask:
            task_id: int
            project: MockProject

        @dataclass(frozen=True)
        class MockHarness:
            name: str

        @dataclass
        class MockArtifacts:
            build_config: project.BuildConfig

            @contextlib.asynccontextmanager
            async def run(self, env={}, mounts={}, timeout=1, group=docker.DockerGroup.Misc, full_callback=None, **kwargs):
                async with docker.run("test", mounts=mounts, env=env, timeout=timeout, group=group, **kwargs) as run:
                    yield run

        fms: list[fuzzing.FuzzManager] = []
        for i, num_harnesses in enumerate(task_harnesses):
            fm = fuzzing.FuzzManager(None)

            def f(i, num_harnesses):
                proj = MockProject(Path(tmpdir), "foo", project.ProjectInfo(main_repo="", language="c"))
                async def get_fuzzers():
                    return {f'san_{s}':{
                        MockHarness(f"h_{i}_{h}|san_{s}"): fuzzing.FuzzHarnessManager(fm, MockTask(0, proj), h, MockHarness(f"h_{i}_{h}|san_{s}"), MockArtifacts(project.BuildConfig(SANITIZER=f"san_{s}")), fuzzing.CorpusManager(proj, MockHarness(f"h_{i}_{h}"), project.BuildConfig()))
                        for h in range(num_harnesses)
                    } for s in range(sanitizers)}
                return get_fuzzers
            monkeypatch.setattr(fm, "get_fuzzers", f(i, num_harnesses))
            fms.append(fm)


        try:
            async with asyncio.timeout(duration):
                async with asyncio.TaskGroup() as tg:
                    for fm in fms:
                        print(f"launching fm {fm}")
                        _ = tg.create_task(fm.run())
                        # wait 1 tick
                        await asyncio.sleep(1/ticks_per_sec)
        except TimeoutError:
            print("done")

        print(machine_used)
        for i in range(machines):
            assert machine_used[f"10.0.3.{i+10}"], f"host {i}/{machines} not used!"

        print(work_completed)
        assert len(machine_workers) <= machines, "too many machines used"
        assert work_completed.values(), "no work was done"
        for i, num_harnesses in enumerate(task_harnesses):
            for h in range(num_harnesses):
                for s in range(sanitizers):
                    assert f"h_{i}_{h}|san_{s}" in work_completed, "some harnesses skipped!"

        # either max-min is off by a factor of <2, or absolute count of <3
        task_works: list[int] = []
        for i, _ in enumerate(task_harnesses):
            vals = [v for k,v in work_completed.items() if k.startswith(f"h_{i}_") and k.endswith("san_0")]
            assert (min(vals) * 2 > max(vals) or (min(vals) > 0 and min(vals) + 4 > max(vals))), f"scheduling too unfair in t_{i}"

            # for alternate sanitizers, expect fairness amongst themselves
            alt_vals = [v for k,v in work_completed.items() if k.startswith(f"h_{i}_") and not k.endswith("san_0")]
            if alt_vals:
                assert (min(alt_vals) * 2 > max(alt_vals) or (min(alt_vals) > 0 and min(alt_vals) + 4 > max(alt_vals))), f"scheduling too unfair in alts for t_{i}"
                # and they didn't run more than the "normal" ones
                assert max(alt_vals) <= min(vals), "alts taking too many resources"
            task_works.append(sum(vals) + sum(alt_vals))

        assert (
            min(task_works) * 2 > max(task_works) or (min(task_works) > 0 and min(task_works) + 4 > max(task_works))
        ), f"scheduling too unfair between tasks"

        assert sum(work_completed.values()) / ((duration - 1) * ticks_per_sec * machines * cores) > 0.95, "scheduling too inefficient"
