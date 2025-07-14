from crs.agents.crsbase import CRSBase
from crs.modules.testing import TestProject

import pickle

async def test_crs_serialization(project: TestProject):
    task = (await project.tasks()).unwrap()[0]
    crs = CRSBase.from_task(task)
    pickled = pickle.dumps(crs)
    assert len(pickled) < 1024*1024, "pickled CRS larger than expected - if this is intentional, increase this limit"
    crs2 = pickle.loads(pickled)
    assert isinstance(crs2, CRSBase)

async def test_sanitizer_descs(project: TestProject):
    if project.info.language != 'java': return
    task = (await project.tasks()).unwrap()[0]
    crs = CRSBase.from_task(task)
    assert (await crs.get_sanitizer_description("SqlInjection")).is_ok()
    assert (await crs.get_sanitizer_description("sql injection")).is_ok()
    assert (await crs.get_sanitizer_description("sqli")).is_err()