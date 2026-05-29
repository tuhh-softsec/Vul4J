import functools
import os
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path
from typing import List

import git
from loguru import logger

from vul4j.config import VUL4J_GIT, JAVA7_HOME, JAVA8_HOME, SPOTBUGS_PATH, \
    MODIFICATION_EXTRACTOR_PATH, DATASET_PATH, SPOTBUGS_VERSION, VUL4J_DATA, JAVA11_HOME, MVN_ARGS, JAVA16_HOME, \
    REPRODUCTION_DIR, TEMP_CLONE_DIR

SEPARATOR = 60 * "-"
THICK_SEPARATOR = 60 * "="


def suffix_filename(filename: str, suffix: str):
    """
    Puts version in the filename if needed.
    """
    name_list = filename.split(".")
    return f"{name_list[0]}_{suffix}.{name_list[1]}" if suffix else ".".join(name_list)


def log_frame(title: str):
    def decorator_log_frame(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = f" START {title} "
            logger.info(start.center(60, "="))
            try:
                func(*args, **kwargs)
            except Exception as err:
                logger.error(f"{err.__class__.__name__}: {err}")
                exit(1)
            finally:
                reset_vul4j_git()
                end = f" END {title} "
                logger.info(end.center(60, "="))

        return wrapper

    return decorator_log_frame


def reset_vul4j_git():
    if os.path.exists(os.path.join(VUL4J_GIT, ".git")):
        repo = git.Repo(VUL4J_GIT)
        repo.git.reset("--hard")
        repo.git.checkout("--")
        repo.git.clean("-fdx", "-e", ".venv")
        repo.git.checkout("-f", "main")


def check_status():
    """
    Checks availability of vul4j dependencies.
    """

    # check vul4j.ini
    vul4j_config = check_config()

    # check vul4j git
    vul4j_git = bool(VUL4J_GIT) and os.path.exists(os.path.join(VUL4J_GIT, ".git"))

    # check vul4j dataset
    vul4j_dataset = bool(DATASET_PATH) and os.path.exists(DATASET_PATH)

    # check java versions
    java_version_command = "java -version"

    java7 = "1.7" in str(subprocess.run(java_version_command,
                                        shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        env=get_java_home_env('7')))

    java8 = "1.8" in str(subprocess.run(java_version_command,
                                        shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        env=get_java_home_env('8')))

    java11 = "11" in str(subprocess.run(java_version_command,
                                        shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        env=get_java_home_env('11')))

    java16 = "16" in str(subprocess.run(java_version_command,
                                        shell=True,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        env=get_java_home_env('16')))

    # check maven
    maven = subprocess.run("mvn -version",
                           shell=True,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL).returncode == 0

    # check spotbugs
    spotbugs = (bool(SPOTBUGS_PATH) and
                subprocess.run(f"java -jar {SPOTBUGS_PATH} -textui -version",
                               shell=True,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL).returncode == 0)

    # check method getter
    modification_extractor = (bool(MODIFICATION_EXTRACTOR_PATH) and
                              subprocess.run(f"java -jar {MODIFICATION_EXTRACTOR_PATH} -version",
                                             shell=True,
                                             stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL,
                                             env=get_java_home_env('16')).returncode == 0)

    def log_result(message: str, success: bool):
        logger.log("SUCCESS" if success else "ERROR", f"{message}: {'OK' if success else 'NOT FOUND'}")

    log_result("VUL4J config file", vul4j_config)
    log_result("VUL4J git repository", vul4j_git)
    log_result("VUL4J dataset", vul4j_dataset)
    log_result("Java 7", java7)
    log_result("Java 8", java8)
    log_result("Java 11", java11)
    log_result("Java 16", java16)
    log_result("Maven", maven)
    log_result("Spotbugs", spotbugs)
    log_result("Spotbugs modification extractor", modification_extractor)


def check_config():
    """
    Check if vul4j is configured correctly.
    """

    errors = []

    if not os.path.exists(os.path.join(VUL4J_DATA, "vul4j.ini")):
        logger.critical("The vul4j.ini file does not exist!")
        return False

    if is_relative_to(REPRODUCTION_DIR, VUL4J_GIT):
        errors.append("The reproduction directory must be outside the vul4j git directory.")

    if is_relative_to(TEMP_CLONE_DIR, VUL4J_GIT):
        errors.append("The temporary clone directory must be outside the vul4j git directory.")

    if is_relative_to(SPOTBUGS_PATH, VUL4J_GIT):
        errors.append("The spotbugs directory must be outside the vul4j git directory.")

    for error in errors:
        logger.error(f"CONFIG ERROR - {error}")
    if errors:
        logger.warning("Please modify the vul4j.ini file or environment variables to resolve the error.")

    return not bool(errors)


def init_data_dir(location: str = None) -> None:
    data_dir = Path(location or VUL4J_DATA).expanduser()
    if data_dir.exists():
        raise RuntimeError(f"Directory already exists: {data_dir}")

    data_dir.mkdir(parents=True)
    (data_dir / "logs").mkdir()
    shutil.copy(Path(__file__).with_name("vul4j.ini"), data_dir / "vul4j.ini")
    logger.success(f"Data directory and files setup at: {data_dir}")


def get_spotbugs(location: str = None) -> None:
    """
    Downloads Spotbugs. The version can be specified in the config file. Default is 4.8.5.
    """

    download_dir = VUL4J_DATA if location is None else location
    os.makedirs(download_dir, exist_ok=True)
    zip_file_path = os.path.join(download_dir, f"spotbugs-{SPOTBUGS_VERSION}.zip")

    logger.info(f"Downloading spotbugs zip to: {zip_file_path}")
    urllib.request.urlretrieve(
        f"https://github.com/spotbugs/spotbugs/releases/download/{SPOTBUGS_VERSION}/spotbugs-{SPOTBUGS_VERSION}.zip",
        zip_file_path)

    logger.info(f"Extracting zip to {VUL4J_DATA}")
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(VUL4J_DATA)

    # delete the zip file
    logger.info("Removing spotbugs zip...")
    os.remove(zip_file_path)


def clean_build(project_dir: str, build_system: str, env: dict) -> None:
    """
    Removes build leftovers.

    :param project_dir: path to the project to be cleaned
    :param build_system: maven or gradle
    :param env: environmental variables with correct java version set
    """

    if build_system == "Maven":
        cmd = "mvn clean"
    elif build_system == "Gradle":
        cmd = "./gradlew clean"
    else:
        logger.error(f"Cleaning not implemented for {build_system}")
        return

    logger.debug(cmd)
    logger.info("Cleaning project...")
    try:
        subprocess.run(cmd,
                       shell=True,
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL,
                       cwd=project_dir,
                       env=env,
                       check=True)
    except subprocess.CalledProcessError:
        logger.error("Clean failed!")


def get_java_home_env(java_version: str) -> dict:
    """
    Returns a copy of *os.environ* where the specified java version and all other java options are set.

    :param java_version: java version
    :return: env with all java parameters set
    """
    try:
        version = int(java_version)

        if version <= 7:
            java_home = JAVA7_HOME
        elif version == 8:
            java_home = JAVA8_HOME
        elif version == 11:
            java_home = JAVA11_HOME
        else:
            java_home = JAVA16_HOME

        assert java_home is not None, f"Java home not set for version {java_version}!"
        logger.debug(f"java home: {java_home}")

        env = os.environ.copy()
        maven_home = env.get("MAVEN33_HOME") if version <= 7 else env.get("MAVEN_HOME", env.get("M2_HOME", ""))
        env["JAVA_HOME"] = java_home
        env["PATH"] = os.path.join(java_home, "bin") + os.pathsep + env["PATH"]
        if maven_home:
            env["MAVEN_HOME"] = maven_home
            env["M2_HOME"] = maven_home
            env["PATH"] = os.path.join(maven_home, "bin") + os.pathsep + env["PATH"]
        env["VUL4J_GIT"] = VUL4J_GIT
        env["JAVA_OPTIONS"] = "-Djdk.net.URLClassPath.disableClassPathURLCheck=true"
        env["MAVEN_OPTS"] = MVN_ARGS
        return env
    except ValueError:
        raise AssertionError(f"Illegal java version: {java_version}")


def find_test_reports(project_dir: str) -> List[str]:
    report_files = []
    for r, dirs, files in os.walk(project_dir):
        for file in files:
            file_path = os.path.join(r, file)
            if (("target/surefire-reports" in file_path
                 or "target/failsafe-reports" in file_path
                 or "build/test-results" in file_path)  # gradle
                    and file.endswith('.xml') and file.startswith('TEST-')):
                report_files.append(file_path)
    return report_files


def evaluate_reproduction_results(results: dict):
    if results["tests_ran"] and results["has_tests"]:
        tests_status = "PASS"
    elif results["tests_ran"] or results["has_tests"]:
        tests_status = "ERROR"
    else:
        tests_status = "SKIP"

    if results["spotbugs_ran"] and results["spotbugs_ok"] and results["has_spotbugs_warnings"]:
        spotbugs_status = "PASS"
    elif results["spotbugs_ran"] or results["spotbugs_ok"] or results["has_spotbugs_warnings"]:
        spotbugs_status = "ERROR"
    else:
        spotbugs_status = "SKIP"

    if ((tests_status == "PASS" and spotbugs_status == "SKIP") or
            (tests_status == "SKIP" and spotbugs_status == "PASS") or
            (tests_status == "PASS" and spotbugs_status == "PASS")):
        log_level = "SUCCESS"
    elif tests_status in {"ERROR", "SKIP"} and spotbugs_status in {"ERROR", "SKIP"}:
        log_level = "ERROR"
    else:
        log_level = "WARNING"

    return log_level, tests_status, spotbugs_status


def is_relative_to(path: str, base: str) -> bool:
    abs_path = os.path.abspath(path)
    abs_base = os.path.abspath(base)
    return abs_path.startswith(abs_base + os.sep)
