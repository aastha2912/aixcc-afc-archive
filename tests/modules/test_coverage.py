import random
import tempfile

from crs.common.aio import Path
from crs.modules.testing import TestProject
from crs.modules.coverage import CoverageAnalyzer, CoverageDB

TEST_DIR = Path(__file__).parent
SUPPORTED_LANGUAGES = {"c", "c++", "jvm"}

rand = random.Random(0x13371337)

async def test_coverage_indexing(built_project: TestProject):
    with tempfile.NamedTemporaryFile() as tf:
        coverage = CoverageAnalyzer(built_project)
        coverage.db = CoverageDB(Path(tf.name)) # use a temporary coverage DB
        if built_project.info.language not in SUPPORTED_LANGUAGES:
            return
        assert await coverage.supports_coverage(), f"coverage not supported for project '{built_project.name}'"


        cov = (await coverage.compute_coverage(harness_num := 0, contents := b"\x00"*100)).unwrap()
        covered_lines = list(cov.iter_covered_lines())
        assert len(covered_lines) > 0, "No covered lines"
        await coverage.db.store_coverage(harness_num, contents, cov)
        for file, line in rand.sample(covered_lines, min(len(covered_lines), 50)):
            _ = (await coverage.db.get_input_for_line(harness_num, file, line)).unwrap()
        missed_lines = list(cov.iter_missed_lines())
        for file, line in rand.sample(missed_lines, min(len(missed_lines), 50)):
            assert (await coverage.db.get_input_for_line(harness_num, file, line)).is_err(), "found coverage for missed line"
