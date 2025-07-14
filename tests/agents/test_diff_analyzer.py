from crs.modules.testing import TestProject
from crs.agents.diff_analyzer import CRSDiff
from crs.common.utils import gather_dict

async def test_diff_agent(project: TestProject, vuln_commits_ignoring: set[int]):
    tasks = (await project.tasks()).unwrap()

    agents = {c: CRSDiff.from_task(tasks[c]).analyze_diff() for c in vuln_commits_ignoring}
    for commit_num, res in (await gather_dict(agents)).items():
        dat = res.unwrap()
        assert len(dat.vuln) > 0, f"no vulns for commit {commit_num}"
