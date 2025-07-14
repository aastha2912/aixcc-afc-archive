# New CRS Evals

The evals operate on a sqlite3 db which is separate but similar to our products db. The cli entrypoints in the evals all take a `--db` param pointing to the eval db.

* `crs/eval/ingest.py`: extracts reports from a backup, produces `reports` and `clusters` (deduped reports) rows in the eval db
* `crs/eval/label.py`: labels the clusters as true/false positive (best effort, uses two different `VulnAnalyzer` passes), and produces a `vuln` row for each true positive
* `crs/eval/pov_produce.py`: runs the pov producer a random sampling of vulns (if passed `--samples N --seed foobar`) or on a specific vuln (if passed `--vuln-id`)
* `crs/eval/vuln_score.py`: runs the vuln scoring a random sampling of labeled reports (if passed `--samples N --seed foobar`) or on a specific report (if passed `--report-id`)

Things currently missing that I may add if I have time (or someone else can if they want it sooner):
* `ingest.py` could also ingest `vulns` from the backup db - the code would look very similar to how we ingest reports
* vuln deduping evals


If you just want to run pov producer evals, you probably just care about something like these:
```
MODEL_MAP=configs/models-best-no-azure.toml python -m crs.eval.pov_produce --db eval.db --vuln-id 37
```
or
```
MODEL_MAP=configs/models-best-no-azure.toml python -m crs.eval.pov_produce --db eval.db --samples 20 --seed myseed
```
