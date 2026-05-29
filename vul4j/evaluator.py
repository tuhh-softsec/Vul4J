import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger

import vul4j.spotbugs as spotbugs
import vul4j.vul4j_tools as vul4j_tools
from vul4j.config import VUL4J_OUTPUT


@dataclass(frozen=True)
class PatchCandidate:
    name: str
    diff: str


@dataclass(frozen=True)
class EvaluationTarget:
    vul_id: str
    candidates: list[PatchCandidate]


class PatchApplyError(RuntimeError):
    pass


def load_targets(path: str, only: list[str] | None = None) -> list[EvaluationTarget]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    selected = {normalize_vul_id(vul_id) for vul_id in only or []}
    targets = [parse_target(item) for item in data]
    return [target for target in targets if not selected or target.vul_id in selected]


def parse_target(item: dict[str, Any]) -> EvaluationTarget:
    candidates = [
        PatchCandidate(
            name=str(candidate.get("name", f"candidate{index + 1}")),
            diff=candidate["diff"],
        )
        for index, candidate in enumerate(item["candidates"])
    ]
    return EvaluationTarget(normalize_vul_id(item["vul_id"]), candidates)


def normalize_vul_id(value: str) -> str:
    text = str(value).strip().upper()
    return text if text.startswith("VUL4J-") else f"VUL4J-{text}"


def apply_unified_diff(project_dir: Path, diff: str) -> None:
    if not diff.strip():
        raise PatchApplyError("empty diff")

    result = subprocess.run(
        ["git", "apply", "--whitespace=nowarn", "-"],
        cwd=project_dir,
        input=diff,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise PatchApplyError((result.stderr or result.stdout).strip())


def reset_checkout(project_dir: Path) -> None:
    for command in (["git", "reset", "--hard", "HEAD"], ["git", "clean", "-fdx"]):
        subprocess.run(
            command,
            cwd=project_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )


class VUL4JEvaluator:
    def __init__(
        self,
        input_file: str,
        output_file: str,
        work_dir: str = "/tmp/vul4j-evaluation",
        output_dir: str | None = None,
        only: list[str] | None = None,
        apply_only: bool = False,
    ):
        self.input_file = input_file
        self.output_file = output_file
        self.work_dir = Path(work_dir)
        self.output_dir = Path(output_dir) if output_dir else None
        self.only = only
        self.apply_only = apply_only
        self.work_dir.mkdir(parents=True, exist_ok=True)
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> list[dict[str, Any]]:
        targets = load_targets(self.input_file, self.only)
        results = [self.evaluate_target(target) for target in targets]
        output_path = Path(self.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        self.log_summary(results)
        return results

    def evaluate_target(self, target: EvaluationTarget) -> dict[str, Any]:
        project_dir = self.work_dir / target.vul_id
        result = {
            "vul_id": target.vul_id,
            "status": "FAILING",
            "reason": None,
            "candidates": [],
            "timestamp": datetime.now().isoformat(),
        }

        try:
            logger.info(f"Checking out {target.vul_id}")
            vul4j_tools.checkout(target.vul_id, str(project_dir), force=True)
            vul = vul4j_tools.Vulnerability.from_json(str(project_dir))

            for candidate in target.candidates:
                reset_checkout(project_dir)
                candidate_result = self.evaluate_candidate(vul, project_dir, candidate)
                result["candidates"].append(candidate_result)

            passing = [item for item in result["candidates"] if item["status"] == "PASSING"]
            if passing:
                result["status"] = "PASSING"
                result["chosen_candidate"] = passing[0]["name"]
            elif self.apply_only and all(
                item["status"] == "PATCH_APPLIED" for item in result["candidates"]
            ):
                result["status"] = "PATCHES_APPLIED"
            else:
                result["reason"] = "NO_PASSING_CANDIDATE"
        except Exception as err:
            logger.error(f"{target.vul_id}: {err}")
            result["reason"] = f"UNKNOWN_ERROR: {err}"
        finally:
            if project_dir.exists() and os.environ.get("KEEP_CHECKOUTS") != "1":
                shutil.rmtree(project_dir, ignore_errors=True)

        return result

    def evaluate_candidate(
        self,
        vul: vul4j_tools.Vulnerability,
        project_dir: Path,
        candidate: PatchCandidate,
    ) -> dict[str, Any]:
        result = {
            "name": candidate.name,
            "status": "FAILING",
            "reason": None,
            "test_results": None,
            "warnings": [],
            "remaining_warnings": [],
        }

        try:
            apply_unified_diff(project_dir, candidate.diff)
        except PatchApplyError as err:
            result["status"] = "PATCH_APPLICATION_ERROR"
            result["reason"] = str(err)
            self.write_artifacts(vul.vul_id, candidate, result, project_dir)
            return result

        if self.apply_only:
            result["status"] = "PATCH_APPLIED"
            self.write_artifacts(vul.vul_id, candidate, result, project_dir)
            return result

        try:
            vul4j_tools.build(str(project_dir), clean=True)
        except (AssertionError, subprocess.CalledProcessError) as err:
            result["status"] = "COMPILATION_ERROR"
            result["reason"] = str(err)
            self.write_artifacts(vul.vul_id, candidate, result, project_dir)
            return result

        if vul.test_cmd:
            try:
                test_results = vul4j_tools.test(str(project_dir), "povs")
            except (AssertionError, subprocess.CalledProcessError) as err:
                result["status"] = "TEST_EXECUTION_ERROR"
                result["reason"] = str(err)
                self.write_artifacts(vul.vul_id, candidate, result, project_dir)
                return result

            result["test_results"] = test_results
            metrics = test_results["tests"]["overall_metrics"]
            if metrics["number_running"] == 0:
                result["reason"] = "NO_TESTS_RAN"
                self.write_artifacts(vul.vul_id, candidate, result, project_dir)
                return result
            if metrics["number_failing"] or metrics["number_error"]:
                result["reason"] = "TEST_NOT_PASSING"
                self.write_artifacts(vul.vul_id, candidate, result, project_dir)
                return result

        target_warnings = [warning for warning in vul.warning if warning]
        if target_warnings:
            try:
                warnings = spotbugs.run_spotbugs(str(project_dir))
            except (AssertionError, StopIteration, subprocess.CalledProcessError) as err:
                result["status"] = "SAST_ERROR"
                result["reason"] = str(err)
                self.write_artifacts(vul.vul_id, candidate, result, project_dir)
                return result

            result["warnings"] = warnings
            result["remaining_warnings"] = [
                warning for warning in target_warnings if warning in warnings
            ]
            if result["remaining_warnings"]:
                result["reason"] = "SAST_WARNINGS_PRESENT"
                self.write_artifacts(vul.vul_id, candidate, result, project_dir)
                return result

        result["status"] = "PASSING"
        self.write_artifacts(vul.vul_id, candidate, result, project_dir)
        return result

    def write_artifacts(
        self,
        vul_id: str,
        candidate: PatchCandidate,
        result: dict[str, Any],
        project_dir: Path,
    ) -> None:
        if not self.output_dir:
            return

        candidate_dir = self.output_dir / vul_id / candidate.name
        candidate_dir.mkdir(parents=True, exist_ok=True)
        (candidate_dir / "patch.diff").write_text(candidate.diff, encoding="utf-8")
        (candidate_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

        vul4j_dir = project_dir / VUL4J_OUTPUT
        if vul4j_dir.exists():
            shutil.copytree(vul4j_dir, candidate_dir / VUL4J_OUTPUT, dirs_exist_ok=True)

    @staticmethod
    def log_summary(results: list[dict[str, Any]]) -> None:
        total = len(results)
        passing = sum(1 for result in results if result["status"] == "PASSING")
        applied = sum(1 for result in results if result["status"] == "PATCHES_APPLIED")
        logger.info(f"Evaluated {total} vulnerabilities")
        logger.info(f"Passing: {passing}")
        if applied:
            logger.info(f"Patches applied: {applied}")
