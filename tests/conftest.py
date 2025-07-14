from typing import Generator
import pathlib
import pytest
import pytest_asyncio
import tomllib

from crs_rust import logger
from crs import config
from crs.common import aio
from collections import defaultdict
from crs.modules.testing import TestProject
import crs.agents.agent

logger.set_pytest_mode()

crs.agents.agent.DEFAULT_TEMP = 0.0

PROJECTS_DIR = config.CRSROOT / '..' / 'projects'

VULN_COMMITS: defaultdict[str, set[int]] = defaultdict(set, {
    "nginx-asc": {0, 11, 21, 88, 122, 183},
    "tomcat-theori": {38, 39, 40},
    "curl-theori": {48, 49},
    "example-libpng-theori": {37, 38, 39},
    "zstd-theori": {47, 48, 49},
    "afc-zookeeper": {40},
    "afc-libxml2": {40, 43},
    "afc-integration-test": {31},
    "afc-freerdp": {40},
    "afc-commons-compress": {37, 40},
    #"afc-sqlite3": {40},
})

IGNORE_COMMITS: defaultdict[str, set[int]] = defaultdict(set, {
    "nginx-asc": {0, 183},
    "zstd-theori": {47}, # flaky
})

# projects which build quickly enough with infer to use in tests
INFER_PROJECTS: set[str] = {"example-libpng-theori"}

project_dirs = list([aio.Path(p) for p in pathlib.Path(PROJECTS_DIR).iterdir()])

@pytest_asyncio.fixture(params=project_dirs, scope="session")
async def project(request: pytest.FixtureRequest) -> TestProject:
    return await TestProject.from_dir(request.param)

@pytest_asyncio.fixture(scope="session")
async def built_project(project: TestProject) -> TestProject:
    _ = (await project.init_harness_info()).expect(f"could not build harnesses for project '{project.name}'")
    return project

@pytest_asyncio.fixture(scope="session")
async def any_project() -> TestProject:
    return await TestProject.from_dir(project_dirs[0])

@pytest_asyncio.fixture(scope="session")
async def any_c_project() -> TestProject:
    return await TestProject.from_dir(PROJECTS_DIR / "nginx-asc")

@pytest_asyncio.fixture(scope="session")
async def any_java_project() -> TestProject:
    return await TestProject.from_dir(PROJECTS_DIR / "tomcat-theori")

@pytest_asyncio.fixture(scope="session")
async def any_built_project(any_project: TestProject) -> TestProject:
    _ = (await any_project.init_harness_info()).expect("could not build harnesses")
    return any_project

@pytest_asyncio.fixture(
    params=[p for p in project_dirs if p.name in INFER_PROJECTS],
    scope="session"
)
async def infer_project(request: pytest.FixtureRequest) -> TestProject:
    return await TestProject.from_dir(request.param)

@pytest.fixture
def vuln_commits(project: TestProject) -> set[int]:
    return VULN_COMMITS[project.name]

@pytest.fixture
def vuln_commits_ignoring(project: TestProject) -> set[int]:
    return VULN_COMMITS[project.name] - IGNORE_COMMITS[project.name]

def model_fixture(model: str) -> Generator[None, None, None]:
    token = config.MODEL.set(model)
    try:
        yield
    finally:
        config.MODEL.reset(token)

def model_map_fixture(model_map: dict[str, str]) -> Generator[None, None, None]:
    token = config.MODEL_MAP.set(model_map)
    try:
        yield
    finally:
        config.MODEL_MAP.reset(token)

@pytest.fixture
def sonnet() -> Generator[None, None, None]:
    yield from model_fixture("claude-3-5-sonnet-20241022")

@pytest.fixture
def gpt_4_1() -> Generator[None, None, None]:
    yield from model_fixture("gpt-4.1-2025-04-14")

@pytest.fixture
def gpt_4o() -> Generator[None, None, None]:
    yield from model_fixture("gpt-4o-2024-08-06")

@pytest.fixture
def best_models() -> Generator[None, None, None]:
    best_map = tomllib.loads(pathlib.Path(config.CRSROOT / ".." / "configs" / "models-best.toml").read_text())
    yield from model_map_fixture(best_map)

def pytest_collection_modifyitems(items: list[pytest.Item]):
    pytest_asyncio_tests = (item for item in items if pytest_asyncio.is_async_test(item))
    session_scope_marker = pytest.mark.asyncio(loop_scope="session")
    for async_test in pytest_asyncio_tests:
        async_test.add_marker(session_scope_marker, append=False)
