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


@pytest.mark.asyncio
async def test_get_repo_diff_accepts_repo_relative_modified_paths():
    with tempfile.NamedTemporaryFile() as tf:
        _ = tarfile.open(tf.name, "w").close()
        e = Editor(vfs := EditableOverlayFS(await TarFS.fsopen(aio.Path(tf.name))))
        await vfs.write("cms_universal_transform_fuzzer.c", b"int main(void) { return 0; }\n")
        await e.apply_patch(
            "cms_universal_transform_fuzzer.c",
            "@@ -1 +1 @@\n-int main(void) { return 0; }\n+int main(void) { return 1; }\n",
        )

        diff = await e.get_repo_diff("lcms")

        assert diff
        assert "--- a/cms_universal_transform_fuzzer.c" in diff
        assert "+++ b/cms_universal_transform_fuzzer.c" in diff
        assert "+int main(void) { return 1; }" in diff


@pytest.mark.asyncio
async def test_apply_patch_normalizes_unique_suffix_path():
    with tempfile.NamedTemporaryFile() as tf:
        _ = tarfile.open(tf.name, "w").close()
        e = Editor(vfs := EditableOverlayFS(await TarFS.fsopen(aio.Path(tf.name))))
        await vfs.write(
            "ffmpeg/libavcodec/wmalosslessdec.c",
            b"static int decode_tilehdr(void) {\n    return 0;\n}\n",
        )

        result = await e.apply_patch(
            "libavcodec/wmalosslessdec.c",
            "@@ -1,3 +1,7 @@\n static int decode_tilehdr(void) {\n+    if (1) {\n+        return -1;\n+    }\n     return 0;\n }\n",
        )

        assert result.is_ok()
        edited = await e.vfs.read("ffmpeg/libavcodec/wmalosslessdec.c")
        assert b"return -1;" in edited


@pytest.mark.asyncio
async def test_apply_patch_normalizes_repo_prefix_mismatch():
    with tempfile.NamedTemporaryFile() as tf:
        _ = tarfile.open(tf.name, "w").close()
        e = Editor(vfs := EditableOverlayFS(await TarFS.fsopen(aio.Path(tf.name))))
        await vfs.write(
            "libjxl/lib/jxl/icc_codec.cc",
            (
                b"void UnpredictICC() {\n"
                b"  shuffled[i] = enc[pos + i];\n"
                b"  pos += num;\n"
                b"}\n"
            ),
        )

        result = await e.apply_patch(
            "lib/jxl/icc_codec.cc",
            (
                "@@ -1,4 +1,4 @@\n"
                " void UnpredictICC() {\n"
                "-  shuffled[i] = enc[pos + i];\n"
                "-  pos += num;\n"
                "+  shuffled[i] = enc[cpos + i];\n"
                "+  cpos += num;\n"
                " }\n"
            ),
        )

        assert result.is_ok()
        edited = await e.vfs.read("libjxl/lib/jxl/icc_codec.cc")
        assert b"enc[cpos + i]" in edited
        assert b"cpos += num;" in edited


@pytest.mark.asyncio
async def test_resolve_path_returns_full_repo_path():
    with tempfile.NamedTemporaryFile() as tf:
        _ = tarfile.open(tf.name, "w").close()
        e = Editor(vfs := EditableOverlayFS(await TarFS.fsopen(aio.Path(tf.name))))
        await vfs.write("libjxl/lib/jxl/icc_codec.cc", b"// test\n")

        resolved = await e.resolve_path("lib/jxl/icc_codec.cc")

        assert resolved == "libjxl/lib/jxl/icc_codec.cc"


@pytest.mark.asyncio
async def test_resolve_path_recovers_repo_root_prefixed_suffix():
    with tempfile.NamedTemporaryFile() as tf:
        _ = tarfile.open(tf.name, "w").close()
        e = Editor(vfs := EditableOverlayFS(await TarFS.fsopen(aio.Path(tf.name))))
        await vfs.write("matio/hdf5-1.12.0/src/H5Oattr.c", b"/* test */\n")

        resolved = await e.resolve_path("hdf5-1.12.0/src/H5Oattr.c")

        assert resolved == "matio/hdf5-1.12.0/src/H5Oattr.c"
