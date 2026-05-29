## Introduction
**Vul4J** is a dataset of real-world Java vulnerabilities. 
Each vulnerability in the [dataset](dataset/vul4j_dataset.csv) is provided along with a human patch, Proof-of-Vulnerability (PoV) test case(s), and other information for the reproduction of the vulnerability.

In this repository, we host the Vul4J dataset, the support framework that allows performing several common tasks required by APR tools on the dataset, and the scripts for Patch Filtering.

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.6383527.svg)](https://doi.org/10.5281/zenodo.6383527)

- License for the dataset: CC-BY-4.0
- License for code: GPL-3.0

If you use Vul4J in academic context, please cite:
```bibtex
@inproceedings{vul4j2022,
  title={Vul4J: A Dataset of Reproducible Java Vulnerabilities Geared Towards the Study of Program Repair Techniques},  
  author={Bui, Quang-Cuong and Scandariato, Riccardo and Ferreyra, Nicol{\'a}s E. D{\'\i}az},  
  booktitle={2022 IEEE/ACM 19th International Conference on Mining Software Repositories (MSR)},   
  year={2022},
  pages={464-468},
  doi={10.1145/3524842.3528482}
}
```

* **Reproduction status**: The Docker build from May 20, 2026 completed all 129 dataset entries successfully. The 79 PoV-based entries reproduced, and the 50 SpotBugs-only entries skipped PoV execution as expected while passing their fixed-warning checks. See the reproduction status section below for details.

## Quick Install
### Requirements
* Linux/macOS Machine
* Java 7
* Java 8
* Java 11
* Java 16
* Maven 3
* Python 3.10+
* uv

### Setup steps
1. Clone Vul4J:
```shell
git clone https://github.com/tuhh-softsec/vul4j
```

2. Install Vul4J and create the default data directory:
```shell
uv sync
source .venv/bin/activate
vul4j init
```

This creates a new `vul4j_data` folder in the home directory.
If it already exists, you will need to manually delete it first.
You can find the `vul4j.ini` and log files there.
By default, the reproduction, temporary cloning and spotbugs directories are placed there as well.
You can change these in the `vul4j.ini`.
`uv sync` installs the `vul4j` command into `.venv/bin`; activate the environment once to run `vul4j` directly.
For a custom data directory, set `VUL4J_DATA` to the same path for later commands.

3. Put your configuration information in the file `~/vul4j_data/vul4j.ini`:
```ini
JAVA7_HOME = <path-to-java-7-home-directory>
JAVA8_HOME = <path-to-java-8-home-directory>
JAVA11_HOME = <path-to-java-11-home-directory>
JAVA16_HOME = <path-to-java-16-home-directory>
```
Other configuration values are optional,
if left empty, the environment variables will be checked or a default value will be used.

The `vul4j.ini` within the **vul4j git repository** is just a sample
and will get overridden by certain operations. Make sure to edit the one in your home directory.

4. You can check if everything is installed correctly:
```shell
vul4j status
```

### Local Docker Build
To build a local image with Maven, SpotBugs, and JDK 7/8/11/16 already installed:

```shell
docker build --platform linux/amd64 -t vul4j:local .
```

To start that image as a standalone container:

```shell
./run_docker.sh
```

Or run it directly:

```shell
docker run --platform linux/amd64 -it --rm \
  vul4j:local
```

### Standalone Reproducible Docker Image
This repository makes Vul4J reproducible from a standalone Docker image instead of relying on host Maven or Gradle caches. The container includes the Vul4J repository, Maven settings, SpotBugs, and JDK 7/8/11/16; all build artifacts and dependency caches are populated inside the image.

The Docker build warms dependency caches by running `vul4j reproduce` for the full dataset during image construction:

```shell
docker build --platform linux/amd64 --progress=plain \
  -t vul4j:local .
```

The complete `vul4j reproduce` output from the warmup is written to `/root/vul4j_data/reproduction.txt` inside the image. Samples that finish without being marked reproducible are written to `/root/vul4j_data/failed_vulnerabilities.txt`. 

Several build commands were adjusted to build only the module needed by the PoV test instead of rebuilding unrelated historical reactors. This is used for old Camel, CXF, Struts, Tika, OpenEJB, CAS, Jenkins, and Spring samples where unrelated modules now fail because of stale dependencies, certificates, or release infrastructure.

Gradle samples use `benchmark.init.gradle` with `-PbenchmarkBuild=true`. The init script adds stable repositories such as Maven Central, the Gradle Plugin Portal, Spring release, and JFrog release, and disables nonessential docs/release/publish plugin tasks that are not needed to compile or run benchmark PoVs.

Some samples require small benchmark overlays in `benchmark_patches/`. These are applied after Vul4J applies the requested version and are reserved for compatibility problems that command changes cannot fix, such as flaky PoV timing, PoV tests referencing APIs removed by the human patch, ambiguous historical source compilation, or stale Gradle plugin wiring.

### Reproduction Status
The current standalone image warmup completed the full dataset on May 20, 2026.

| Scope | Entries | Warmup result |
|-------|--------:|---------------|
| PoV-based vulnerabilities, `VUL4J-1` through `VUL4J-79` | 79 | `Vulnerabilities: PASS` |
| SpotBugs-only samples, `VUL4J-80-S` through `VUL4J-129-S` | 50 | `Vulnerabilities: SKIP`, `Spotbugs: PASS` |
| Total | 129 | No failed reproductions recorded |

SpotBugs finished with `PASS` for 52 entries and `SKIP` for 77 entries whose dataset rows do not define fixed warnings. `SKIP` is expected for those rows and does not indicate a reproduction failure.

To verify a built image, inspect the warmup artifacts:

```shell
docker run --rm vul4j:local sh -lc 'test ! -s /root/vul4j_data/failed_vulnerabilities.txt'
docker run --rm vul4j:local sh -lc 'grep -E "Vulnerabilities: ERROR|Spotbugs: ERROR|did not reproduce successfully|Failed vulnerabilities" /root/vul4j_data/reproduction.txt || true'
```

The first command should exit with status 0. The second command should produce no output.

Some historical projects still emit `Clean failed!` during Maven or Gradle cleanup. These cleanup failures are non-fatal when the subsequent compile step and final reproduction status pass.

## Usage
```bash
$ vul4j --help

usage: vul4j [-h] [-l LOG] {init,status,checkout,compile,test,apply,sast,reproduce,verify,info,classpath,get-spotbugs,evaluate} ...

A Dataset of Java vulnerabilities.

positional arguments:
  {init,status,checkout,compile,test,apply,sast,reproduce,verify,info,classpath,get-spotbugs,evaluate}
    init                Create the Vul4J data directory and default config.
    status              Lists vul4j requirements and their availability.
    checkout            Checkout a vulnerability into the specified directory.
    compile             Compile the checked out vulnerability.
    test                Run testsuite for the checked out vulnerability.
    apply               Apply the specified file versions.
    sast                Run Spotbugs analysis.
    reproduce (verify)  Verify the reproducibility of vulnerabilities in the dataset.
    info                Print information about a vulnerability.
    classpath           Print the classpath of the checked out vulnerability.
    get-spotbugs        Download Spotbugs into the user directory.
    evaluate            Evaluate candidate patches from unified git diffs.

options:
  -h, --help            show this help message and exit
  -l, --log LOG         Specify displayed log level for this command.
```

### Evaluating Candidate Patches
`vul4j evaluate` checks generated patch candidates against Vul4J. It is intended for repair tools that produce one or more candidate fixes for a vulnerability and need the same validation pipeline for each candidate. Each candidate is applied to a clean checkout of the vulnerable version, then evaluated with the benchmark's compile command, PoV tests when available, and fixed-warning SpotBugs checks when defined.

Each candidate is a unified Git diff, so patches can modify methods, constructors, fields, imports, or whole files. 
Input files are JSON arrays:

```json
[
  {
    "vul_id": "VUL4J-10",
    "candidates": [
      {
        "name": "candidate1",
        "diff": "diff --git a/src/main/java/Example.java b/src/main/java/Example.java\n--- a/src/main/java/Example.java\n+++ b/src/main/java/Example.java\n@@ -1 +1 @@\n-old\n+new\n"
      }
    ]
  }
]
```

Run evaluation:

```shell
vul4j evaluate patches.json -o evaluation_results.json --output-dir evaluation_artifacts
```

For each candidate, Vul4J checks out the vulnerable revision, applies the diff with `git apply`, compiles the project, runs PoV tests when present, and runs SpotBugs when the dataset defines fixed warnings. A candidate passes when compilation succeeds, PoV tests pass, and the target SpotBugs warnings are gone.

To only apply candidate diffs and export artifacts without compiling or testing:

```shell
vul4j evaluate patches.json --apply-only --output-dir applied_patches
```

## Dataset Execution Framework Demonstration
In this section, we demonstrate how to use the execution framework to check out a vulnerability, then compile and run the test suite and SAST analysis of the vulnerability.
We also demonstrate how to use our framework to validate the reproduction of new vulnerabilities.

0. **Preparation:** You need to install our execution framework first. You could install Vul4J on your machine by following the *Quick Install* section or use our [pre-built Docker image](https://hub.docker.com/r/tuhhsoftsec/vul4j).
In the case, you want to use the pre-built Docker image, use the following command to start the Docker container:
```shell
$ docker run -it --name vul4j tuhhsoftsec/vul4j
```

1. **Checkout a vulnerability:** We will check out the vulnerability with ID *VUL4J-10*, 
which had the CVE identifier CVE-2013-2186 and made the Apache Commons FileUpload vulnerable to Null Byte Injection.
Our desired destination is the directory `/tmp/vul4j/VUL4J-10`.
```shell
$ vul4j checkout --id VUL4J-10 -d /tmp/vul4j/VUL4J-10
```

2. **Compile:** Now we can compile the vulnerability.
```shell
$ vul4j compile -d /tmp/vul4j/VUL4J-10
```

3. **Run Testsuite:** And run the test suite with the presence of the vulnerability in source code.
```shell
$ vul4j test -d /tmp/vul4j/VUL4J-10

# test results found in /tmp/vul4j/VUL4J-10/VUL4J/test_results.json
{
  "vul_id": "VUL4J-10",
  "cve_id": "CVE-2013-2186",
  "repository": {
    "name": "apache_commons-fileupload",
    "url": "https://github.com/apache/commons-fileupload",
    "human_patch_url": "https://github.com/apache/commons-fileupload/commit/163a6061fbc077d4b6e4787d26857c2baba495d1"
  },
  "tests": {
    "overall_metrics": {
      "number_running": 69,
      "number_passing": 67,
      "number_error": 0,
      "number_failing": 2,
      "number_skipping": 0
    },
    "failures": [
      {
        "test_class": "org.apache.commons.fileupload.DiskFileItemSerializeTest",
        "test_method": "testInvalidRepositoryWithNullChar",
        "failure_name": "java.lang.AssertionError",
        "detail": "Expected exception: java.io.IOException",
        "is_error": false
      },
      {
        "test_class": "org.apache.commons.fileupload.DiskFileItemSerializeTest",
        "test_method": "testInvalidRepository",
        "failure_name": "java.lang.AssertionError",
        "detail": "Expected exception: java.io.IOException",
        "is_error": false
      }
    ],
    "passing_tests": [
      "org.apache.commons.fileupload.util.mime.QuotedPrintableDecoderTestCase#invalidQuotedPrintableEncoding",
      "org.apache.commons.fileupload.util.mime.QuotedPrintableDecoderTestCase#unsafeDecodeLowerCase",
      ... 
      "org.apache.commons.fileupload.DefaultFileItemTest#testBelowThreshold"
    ],
    "skipping_tests": []
  }
}
```

4. **Run SAST analysis:** Run Spotbugs analysis on the compiled jar file.
```shell
$ vul4j sast -d /tmp/vul4j/VUL4J-10

# SAST warnings in the vulnerable files
[
  "MC_OVERRIDABLE_METHOD_CALL_IN_READ_OBJECT@org.apache.commons.fileupload.disk.DiskFileItem#readObject",
  "MC_OVERRIDABLE_METHOD_CALL_IN_READ_OBJECT@org.apache.commons.fileupload.disk.DiskFileItem#readObject",
  "MC_OVERRIDABLE_METHOD_CALL_IN_READ_OBJECT@org.apache.commons.fileupload.disk.DiskFileItem#readObject",
  "MC_OVERRIDABLE_METHOD_CALL_IN_READ_OBJECT@org.apache.commons.fileupload.disk.DiskFileItem#readObject",
  "RV_RETURN_VALUE_IGNORED_BAD_PRACTICE@org.apache.commons.fileupload.disk.DiskFileItem#readObject"
]
```
If Spotbugs fails to run, make sure it is installed and the correct path is set in `~/vul4j_data/vul4j.ini`.
You can also install it automatically with `vul4j get-spotbugs`, which installs it inside the configured Vul4J data directory.

5. **Validate reproduction of new vulnerability:** Our framework can validate the reproduction of new vulnerability.
First, you need to provide the essential information about the new vulnerability in the [csv dataset file](dataset/vul4j_dataset.csv) including: `vul_id`, `human_patch_url`, `build_system`, `compliance_level`, `compile_cmd`, `test_all_cmd`.
Then, you can run the following command to check the new vulnerability is reproducible or not. We demonstrate with an existing vulnerability we used in the previous task. 
```shell
$ vul4j reproduce --id VUL4J-10

2024-06-13 20:35:31 | ===================== START REPRODUCE ======================
2024-06-13 20:35:31 | Reproducing 1 vulnerabilities...
2024-06-13 20:35:31 | --------------------------VUL4J-10--------------------------
2024-06-13 20:35:31 | Checking out project...
2024-06-13 20:35:31 | --> Applying version: vulnerable
2024-06-13 20:35:31 | Cleaning project...
2024-06-13 20:35:33 | Compiling...
2024-06-13 20:35:41 | Running PoV tests...
2024-06-13 20:35:46 | Number of running tests: 1
2024-06-13 20:35:46 | Failing tests: [
  "org.apache.commons.fileupload.DiskFileItemSerializeTesttestInvalidRepositoryWithNullChar"
]
2024-06-13 20:35:46 | No fixed warnings found in the dataset for VUL4J-10. Skipping Spotbugs...
2024-06-13 20:35:46 | --> Applying version: human_patch
2024-06-13 20:35:46 | Cleaning project...
2024-06-13 20:35:48 | Compiling...
2024-06-13 20:35:56 | Running PoV tests...
2024-06-13 20:36:01 | Number of running tests: 1
2024-06-13 20:36:01 | Number of passing tests: 1
2024-06-13 20:36:01 | No fixed warnings found in the dataset for VUL4J-10. Skipping Spotbugs...
2024-06-13 20:36:01 | Vulnerabilities: PASS, Spotbugs: SKIP!
2024-06-13 20:36:01 | ====================== END REPRODUCE =======================
```
