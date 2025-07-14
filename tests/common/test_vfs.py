import tempfile
import shutil
from crs.modules.testing import TestProject
from crs.common import process
from crs.common.aio import Path
from crs.common.vfs import DiffOverlayFS, TarFS, MountFS

async def test_vfs_hashing(project: TestProject):
    assert await project.vfs.hash() == await (project.vfs.fork().hash()), "forking should not change hash"

async def test_diff_vfs(project: TestProject):
    repo_path = (await project.repo_path()).unwrap()
    assert (commit_range := project.info.commit_range) is not None
    async with project.vfs.materialized() as src:
        with tempfile.NamedTemporaryFile() as tar:
            res = await process.run_to_res(
                "git", "rev-list", "--first-parent", f"{commit_range.start_ref}^!", commit_range.end_ref,
                cwd=src/repo_path, capture_output=True
            )
            assert res.returncode == 0, f"git rev-list failed: {res.output}"
            hashes = list(reversed(res.output.strip().splitlines()))

            res = await process.run_to_res("git", "checkout", hashes[0], cwd=src/repo_path, capture_output=True)
            assert res.returncode == 0, f"git checkout failed: {res.output}"

            res = await process.run_to_res("tar", "cf", tar.name, "--exclude", ".git", ".", cwd=src/repo_path)
            assert res.returncode == 0, f"tar failed: {res.output}"
            base = await TarFS.fsopen(Path(tar.name))

            res = await process.run_to_res("git", "diff", hashes[0], hashes[-1], cwd=src/repo_path, capture_output=True)
            assert res.returncode == 0, f"git diff failed: {res.output}"
            diff = res.stdout.decode()

            res = await process.run_to_res("git", "checkout", hashes[-1], cwd=src/repo_path, capture_output=True)
            assert res.returncode == 0, f"git checkout failed: {res.output}"

            shutil.rmtree(src / repo_path / ".git")

            with tempfile.NamedTemporaryFile(mode="wb") as tf:
                _ = tf.write(diff.encode())
                tf.flush()
                diff_vfs = DiffOverlayFS(base, Path(tf.name), '.')
                vfs_tree = set((await diff_vfs.tree()).unwrap().all_paths())

                src_path = src / repo_path
                async with src_path.walk() as walk_it:
                    real_tree = set()
                    async for b, _, files in walk_it:
                        for f in files:
                            path = b / f
                            if not await path.is_file():
                                continue
                            real_tree.add(str(path.relative_to(src_path)))
                for f in vfs_tree - real_tree:
                    assert diff_vfs.is_dir(f) or await (src/repo_path/f).is_dir(), f"non-directory wasn't deleted: {f}"

async def test_mountfs(project: TestProject):
    repo_path = (await project.repo_path()).unwrap()
    # mount {repo_path} over itself
    vfs = MountFS(project.vfs, repo_path.as_posix(), project.vfs, repo_path.as_posix())
    # check tree is unchanged
    assert set((await vfs.tree()).unwrap().all_paths()) == set((await project.vfs.tree()).unwrap().all_paths())
