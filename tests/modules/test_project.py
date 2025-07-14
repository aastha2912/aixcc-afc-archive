from pathlib import Path

from crs.common import diff_utils
from crs.modules import project
from crs.modules.testing import TestProject

TEST_DIR = Path(__file__).parent
POV_DIR = TEST_DIR / 'data' / 'povs'

async def test_nested_fork(any_project: TestProject):
    assert any_project.new_fork().new_fork().new_fork().new_fork().new_fork()

async def test_build_project(built_project: TestProject):
    # work happens in the fixture
    pass

async def test_build_pov(any_project: TestProject):
    pov = (await any_project.build_pov("with open('input.bin', 'wb') as f: f.write(b'asdf')")).unwrap()
    assert pov == b'asdf'

    # over max pov length, should fail
    assert (await any_project.build_pov("with open('input.bin', 'wb') as f: f.write(b'asdf' * (1024*1024))")).is_err()

    pov = (await any_project.build_pov(
        "with open('junk.bin', 'wb') as f: f.write(b'asdf' * (1024*1024))\n"
        "with open('input.bin', 'wb') as f: f.write(b'asdf')"
    )).unwrap()
    assert pov == b'asdf'

async def test_povs_triggered(built_project: TestProject):
    tasks = (await built_project.tasks()).unwrap()
    povs = POV_DIR / built_project.name
    if not povs.exists():
        return
    seen_dedup: set[str] = set()
    seen_stack: set[str] = set()
    for path in povs.iterdir():
        commit_num, harness_num = map(int, path.name.split("_")[1:])
        task = tasks[commit_num]
        _ = (await task.project.build_all(capture_output=True)).expect(f"could not build project for task {commit_num}")
        pov = path.read_bytes()
        res = await task.project.test_pov_contents(built_project.check_harness(harness_num).unwrap(), pov)
        assert res.is_ok(), f"POV {path.name} didn't crash, {res.err()}"
        assert len(res.unwrap().stack.splitlines()) > 1
        assert res.unwrap().stack not in seen_stack
        seen_stack.add(res.unwrap().stack)
        assert res.unwrap().dedup not in seen_dedup
        seen_dedup.add(res.unwrap().dedup)

        builds = (await task.project.build_all()).unwrap()
        base_builds = (await task.base.build_all()).unwrap()
        harness = (await task.project.init_harness_info()).unwrap()[harness_num]
        pov_res = await project.run_pov(builds, base_builds, harness.name, pov)
        assert pov_res.is_ok()

        _ = (await task.base.build_all(capture_output=True)).expect(f"could not build base project for task {commit_num}")
        res = await task.base.test_pov_contents(built_project.check_harness(harness_num).unwrap(), pov)
        assert res.is_err(), f"POV {path.name} crashed before commit {commit_num}, {res.unwrap().output}"

PRUNE_TESTS: dict[str, dict[int, set[str]]] = {
    'nginx-asc': {
        21: {'nginx/src/event/ngx_event_openssl_stapling.c'},
        0: {'nginx/src/os/win32/ngx_errno.c', 'nginx/src/os/win32/ngx_win32_init.c'},
        1: set(),
    },
    'tomcat-theori': {
        i: set() for i in range(3)
    },
    'example-libpng-theori': {
        0: set(),
        10: {'libpng/contrib/libtests/pngstest.c', 'libpng/contrib/libtests/pngvalid.c'},
    },
    'zstd-theori': {
        48: set()
    }
}

async def test_diff_pruning(project: TestProject):
    if (tests := PRUNE_TESTS.get(project.name)) is None:
        return
    tasks = (await project.tasks()).unwrap()
    for tid, expected in tests.items():
        task = tasks[tid]
        before = set(diff_utils.iter_prev_paths(task.diff))
        after = set(diff_utils.iter_prev_paths(await task.pruned_diff()))
        pruned = before - after
        for path in pruned:
            assert not await task.project.searcher.compiler_might_use_path(path), f"inconsistent pruning logic for {path}"
        # check that the correct paths are pruned
        assert pruned == expected, f"unexpected pruned paths for task {tid}: {pruned} vs {expected}"