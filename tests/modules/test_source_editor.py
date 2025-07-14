import pathlib
import pytest
import tarfile
import tempfile

from crs.common import aio
from crs.modules.source_editor import *
from crs.common.vfs import *

TEST_DIR = pathlib.Path(__file__).parent

test_cases = [aio.Path(p) for p in (TEST_DIR / 'data' / 'patches').iterdir()]

@pytest.mark.parametrize('base_dir', test_cases)
@pytest.mark.asyncio(scope="session")
async def test_fuzzy_patching(base_dir: aio.Path):
    print("running test", __import__('os').path.basename(base_dir))
    with tempfile.NamedTemporaryFile() as tf:
        _ = tarfile.open(tf.name, "w").close()
        e = Editor(vfs := EditableOverlayFS(await TarFS.fsopen(aio.Path(tf.name))))
        await vfs.write("./input", await (base_dir / 'input').read_bytes())
        patch = await (base_dir / 'patch').read_text()
        output = (base_dir / 'output')
        should_succeed = await output.exists()

        match await e.apply_patch('./input', patch):
            case Ok():
                assert should_succeed
                # assert the update applied as expected
                edited = await e.vfs.read("input")
                expected = await output.read_bytes()
                assert edited == expected
            case Err():
                # assert we should have failed
                assert not should_succeed
                # assert the file is unchanged
                original = await (base_dir / 'input').read_bytes()
                maybe_edited = await e.vfs.read("input")
                assert original == maybe_edited

        if should_succeed:
            # ensure we can undo
            assert (await e.undo_last_patch()).is_ok()
            edited = await e.vfs.read('input')
            original = await (base_dir / 'input').read_bytes()
            assert edited == original
