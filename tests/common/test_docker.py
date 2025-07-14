import asyncio

from crs.common import docker, process

PYTHON_IMAGE = "python:3.12-slim"

async def test_docker_port_discovery():
    container_port = 8000
    async with docker.run(PYTHON_IMAGE, ports=[container_port], timeout=300) as run:
        proc = await run.exec(
            "python3", "-m", "http.server", str(container_port),
        )
        await asyncio.sleep(10)
        host_port = run.port_map[container_port]
        url = f"http://{host_port}/"
        proc_res = await process.run_to_res("curl", "--silent", url)
        assert proc_res.returncode == 0
        proc.kill()
        _ = await proc.wait()
