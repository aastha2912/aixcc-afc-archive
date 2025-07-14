# OSS-Fuzz Project Overview

We have been told that the AIxCC Final Competition project format will be based on the OSS-Fuzz format, likely with some minor extensions. As a result, our CRS takes individual OSS-Fuzz [project directories](https://github.com/google/oss-fuzz/tree/master/projects) as input. For a deeper guide on what these directories contain, check the [OSS-Fuzz docs](https://google.github.io/oss-fuzz/getting-started/new-project-guide/).

This document will
1. explain some minor additions to the OSS-Fuzz format used by our CRS
2. serve as a guide to integrate new projects into our test corpus

## Project Format

The OSS-Fuzz format is quite minimal, and requires only two files:
1. `project.yaml` contains basic metadata about the project, including languages and supported sanitizers
2. `Dockerfile` creates an image derived from `gcr.io/oss-fuzz-base/base-builder`. The image should include all project source code in `$SRC` and have all build dependencies installed. The default entrypoint of the base image will (indirectly) invoke `$SRC/build.sh`, which must build all fuzzers and place them in `$OUT`.

Many projects will include other files as well, e.g. fuzz harnesses code or dictionaries which aren't already present in the source repos.

OSS-Fuzz runs the fuzzers by mounting them into a separate image: `gcr.io/oss-fuzz-base/base-runner`. As a result, all fuzz harnesses should be portable (e.g. statically linked).

## CRS <-> Project Interaction

Our CRS take a project's OSS-Fuzz directory as input. It will
1. run `docker build` to produce the project's builder image
2. copy the `$SRC` directory out of the image and detect the repos within it
3. build the fuzzers (by running the build image) with various configurations (e.g. different sanitizers, coverage mode, etc.)
4. invoke the fuzzers (in the `base-runner` image) in various ways to fuzz, test PoVs, collect coverage info, etc.

The AFC will require our CRS to support two modes:
- *Full mode*: we are given an entire codebase, basically a `$SRC` directory from a normal OSS-Fuzz project
- *Delta mode*: we are given a target repo and a commit range (representative of a PR), and only those changes are in scope.

### Full mode

It is unclear if the organizers will make any changes to the OSS-Fuzz format to support full mode.

Note: our CRS does not yet support full mode, but once it does, we should be able to test our CRS on any OSS-Fuzz project without modifications.

### Delta Mode

The OSS-Fuzz format on its own doesn't specify target repos / revisions and the organizers have not yet described their format for delta mode. So for now, we are simply adding a commit range to the `project.yaml`, e.g.
```yaml
commit_range:
  start_ref: c498a935699a24720cc8857a48d0ce999e1aa6bb
  end_ref: 077e305de7e7f7a960d0ad440e7ed66f3da5a5ce
```

## Integrating Test Projects

The following is a quick guide for integrating an existing OSS-Fuzz project into our testsuite. For now, we are committing the test project directories directly to this repo's `projects/` directory.

Note: at some point, we may set up automated vulnerability injection and testing on [all OSS-Fuzz projects](https://github.com/google/oss-fuzz/tree/master/projects), which will require a more scalable process than what is described below.

### 1. Pick a project

We have a useful [spreadsheet](https://docs.google.com/spreadsheets/d/1iCvoYsEJfYN1iCRwsK5ZbmUbL2r_uXy0xLpdUv2KCfE/edit?gid=0#gid=0) of OSS-Fuzz projects with some useful information about each one. Our goal should be to pick projects that are representative of what we expect to see in finals. Some relevant criteria:
* Langauge - we expect the AFC to contain (very roughly) 60% c/c++, 40% java. We should try pick projects that push our testsuite roughly toward that distribution.
* Impact - high-impact projects are likely to appear in the AFC. Try to select projects that are well-known and whose security has real-world impacts.
* Diversity - beyond language diversity, the AFC will likely assess our CRS's ability to reason about diverse types of software and vulnerability classes.

Once you have a project, create a copy of its project directory under this repo's `projects/` directory, e.g. `projects/{upstream_project_name}-theori`.

**NOTE:** keep the directory names distinct from the upstream OSS-Fuzz project. This will avoid confusion in the future when we test our CRS on all projects.

### 2. Modify the source code

OSS-Fuzz projects' `Dockerfile`s generally `git clone` the project source code into `$SRC`. To inject vulnerabilities into a repo, you can either
1. add additional steps to the `Dockerfile` which apply commits to the repo, or
2. create a private fork of the source repo under the `theori-io` org

If you're doing 1, you may want to use the [pillow-theori project](../projects/pillow-theori/) as an example.

**NOTE:** Dockerfiles from the oss-fuzz project might make a "shallow clone" using the command `RUN git clone --depth 1 http://path/to/repo.git`. In this case, remove the `--depth 1` argument so our clone can properly access previous commits.

If you're doing 2, you may want to use the [tomcat-theori project](../projects/tomcat-theori) as an example. Some notes for this method:
1. grant the AIxCC-dev GitHub team admin access the forked source repo
2. generate a deploy key for the source repo, and use it to clone the private repo in the `Dockerfile`.

### 3. Set up the commit_range

Edit the `project.yaml` file to add the range of commits that the CRS should analyze.

**NOTE:** the commit range should include all added vulnerable commits as well as *AT LEAST* 32 benign commits. The order of the commits does not matter, so one approach is to apply all vulnerable commits on top of the latest upstream revision and then set `end_ref` to `HEAD` and `start_ref` to e.g. `HEAD~50`. The git refs will be properly parsed, so you can literally use the commit_range:

```yaml
commit_range:
  start_ref: HEAD~50
  end_ref: HEAD
```

### 4. OPTIONAL: Update the unit test suite

In `tests/conftest.py`, you can add the set of vulnerable commit numbers (i.e. the indices of the vulnerable commits in the range specified in `project.yaml`) to the `VULN_COMMITS` and `IGNORE_COMMITS` map. The former indicates which commits have bugs, and the latter indicates which of those should be skipped during unit tests (this should typically be `set()`).

Optional: add any PoV blobs for the vulnerabilities to `tests/modules/data/povs/{project_name}/pov_{commit_num}_{harness_num}`. These will be verified to actually crash in our CRS environment by a unit test.

**NOTE:** in the future we may rework whether we run all projects in the unit tests, but for now it is still valuable to add them here.

### 5. Update the eval script

In `eval.py`, you should add brief descriptions of the bugs into the `VULN_COMMITS` map. The keys specify which commits are vulnerable, and the values are used as input to a PoV producer agent. This allows the PoV producer to be tested even if the commit analyzer is unable to provide a vulnerability description.

**NOTE:** in the future we may want to use LLM-generated descriptions instead of hand-written brief bug descriptions.

### 6. Ship it

That's it! You may want to test that the evaluations run as expected on your branch before merging it to main. To do that, follow the instructions in the [README](../README.md) for manually triggering the evaluation workflow on your branch.
