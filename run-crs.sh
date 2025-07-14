#!/usr/bin/env bash

cd "$(dirname "$0")"

CRS_PORT=${CRS_PORT:-1324}
CRS_HOST=${CRS_HOST:-127.0.0.1}

# Loop until 'docker info' succeeds
while ! docker info >/dev/null 2>&1; do
  echo "Waiting for Docker to be available at $DOCKER_HOST..."
  sleep 1
done

run_in_venv () {
    unset crs_done
    sigint_handler () {
        crs_done=1
    }
    trap sigint_handler SIGINT
    while [ -z $crs_done ]; do
        source .venv/bin/activate && "$@"
    done;
    echo "done running: $@"
}

spawn_venv_proc () {
    # run in background and redirect output to our stdout/stderr
    run_in_venv "$@" 1>/proc/$$/fd/1 2>/proc/$$/fd/2 &
}

echo "spawning task_server at ${CRS_HOST}:${CRS_PORT}"
spawn_venv_proc python -m uvicorn --access-log --host ${CRS_HOST} --port ${CRS_PORT} crs.task_server.app:app
spawn_venv_proc python main.py

trap 'wait' SIGINT
wait
