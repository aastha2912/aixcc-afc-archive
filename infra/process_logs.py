#!/usr/bin/env python

from datetime import datetime
from pathlib import Path
from typing import Any
import json

from influxdb_client import InfluxDBClient, Point
from tqdm import tqdm

def is_eval_result(log):
    return (
        log["record"]["function"] in ["main", "_run_eval"] and
        "Evaluation" in log["record"]["message"]
    )

def find_eval_results(logs):
    for log in logs:
        if is_eval_result(log):
            yield log["record"]["extra"]

def gather_data(dir: Path) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = []
    seen_file = Path(".seen.json")
    seen = set(json.loads(seen_file.read_bytes())) if seen_file.exists() else set()
    for branch_dir in tqdm(list(dir.iterdir()), desc="gather branches"):
        for log_file in branch_dir.iterdir():
            if log_file.stat().st_size > 1024*1024*1024:
                print(f"Warning: {log_file} too big")
            timestamp = datetime.fromtimestamp(log_file.stat().st_mtime)
            if log_file.as_posix() in seen:
                continue
            seen.add(log_file.as_posix())
            lines = log_file.read_text().split("\n")
            try:
                logs = [json.loads(line) for line in lines if len(line) > 0 and 'Evaluation' in line]
                for res in find_eval_results(logs):
                    data.append({'branch': branch_dir.name, 'log_file': log_file.name, 'timestamp': timestamp} | res)
            except Exception as e:
                print(f"Error handling {log_file}: {repr(e)}")
    with seen_file.open("w") as f:
        f.write(json.dumps(list(seen)))
    return sorted(data, key=lambda data: data["timestamp"])

def process_logs(dir: Path):
    influx_url = "http://localhost:8086"
    influx_org = "theori"
    influx_bucket = "aixcc"
    with open("/etc/influxdb/wo_token", "r") as f:
        influx_key = f.read().strip()

    client = InfluxDBClient(url=influx_url, token=influx_key, org=influx_org)

    data = gather_data(dir)
    with client.write_api() as write_api:
        for row in tqdm(data, desc="write metrics"):
            p = Point("eval")
            p = p.time(time=row.pop("timestamp"))

            tag_keys = ("branch", "eval", "project", "model", "model_map", "log_file")
            for key in tag_keys:
                if key in row:
                    p = p.tag(key, row[key])
                else:
                    p = p.tag(key, "")

            for k, v in row.items():
                if isinstance(v, (list, dict)):
                    continue
                if k == "time":
                    k = "duration"
                p.field(k, v)
            write_api.write(bucket=influx_bucket, record=p)

if __name__ == "__main__":
    process_logs(Path("./logs"))