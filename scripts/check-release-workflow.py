#!/usr/bin/env python3
"""Validate release workflow dependencies from parsed YAML structures.

This check intentionally complements actionlint.  actionlint validates GitHub
Actions syntax and expressions; this script validates the specific job graph
that protects release publication.  It reads YAML nodes rather than searching
file text, so comments and similarly named jobs cannot satisfy an assertion.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as error:  # pragma: no cover - depends on the runner image
    raise SystemExit(
        "release workflow check requires PyYAML; install the runner's python3-yaml package"
    ) from error


CHECKOUT_REF = "${{ inputs.checkout-ref || github.ref }}"
RELEASE_SHA = "${{ needs.resolve.outputs.sha }}"
RELEASE_TAG_REF = "${{ inputs.tag || github.ref }}"
RUNNIT_LINUX_LABELS = ["self-hosted", "Linux", "X64", "palantir-actions"]
RUNNIT_MACOS_X64_LABELS = ["self-hosted", "macOS", "X64", "palantir-actions"]
RUNNIT_MACOS_ARM64_LABELS = ["self-hosted", "macOS", "ARM64", "palantir-actions"]
REQUIRED_RELEASE_JOBS = {
    "resolve",
    "ci",
    "hardening",
    "secret_scan",
    "gates",
    "build",
    "assemble",
    "publish",
}


class UniqueLoader(yaml.BaseLoader):
    """Preserve GitHub's ``on`` key and reject duplicate YAML mappings."""


def construct_unique_mapping(loader: UniqueLoader, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ValueError(f"mapping key must be a string, got {key!r}")
        if key in mapping:
            raise ValueError(f"duplicate mapping key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def fail(message: str) -> None:
    raise ValueError(message)


def load_workflow(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            document = yaml.load(stream, Loader=UniqueLoader)
    except (OSError, yaml.YAMLError, ValueError) as error:
        fail(f"could not parse {path}: {error}")
    if not isinstance(document, dict):
        fail(f"{path} must contain a YAML mapping")
    if not isinstance(document.get("jobs"), dict):
        fail(f"{path} must define a jobs mapping")
    return document


def mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{context} must be a mapping")
    return value


def sequence(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{context} must be a sequence")
    return value


def required_string(mapping_value: dict[str, Any], key: str, context: str) -> str:
    value = mapping_value.get(key)
    if not isinstance(value, str) or not value:
        fail(f"{context}.{key} must be a non-empty string")
    return value


def needs_set(job: dict[str, Any], job_id: str) -> set[str]:
    value = job.get("needs")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    fail(f"release job {job_id!r}.needs must be a job id or list of job ids")


def workflow_call_input(workflow: dict[str, Any], path: Path) -> None:
    events = mapping(workflow.get("on"), f"{path}.on")
    call = mapping(events.get("workflow_call"), f"{path}.on.workflow_call")
    inputs = mapping(call.get("inputs"), f"{path}.on.workflow_call.inputs")
    checkout = mapping(inputs.get("checkout-ref"), f"{path} checkout-ref input")
    if checkout.get("type") != "string" or checkout.get("required") != "false":
        fail(f"{path} checkout-ref must be an optional string input")
    if path.name == "ci.yml":
        include_macos = mapping(
            inputs.get("include-macos"), f"{path} include-macos input"
        )
        if (
            include_macos.get("type") != "boolean"
            or include_macos.get("required") != "false"
            or include_macos.get("default") != "false"
        ):
            fail(f"{path} include-macos must be an optional boolean input defaulting to false")
    elif "include-macos" in inputs:
        fail(f"{path} must not define the CI-only include-macos input")


def checkout_steps(workflow: dict[str, Any], path: Path) -> None:
    jobs = mapping(workflow["jobs"], f"{path}.jobs")
    for job_id, raw_job in jobs.items():
        job = mapping(raw_job, f"{path}.jobs.{job_id}")
        steps = sequence(job.get("steps"), f"{path}.jobs.{job_id}.steps")
        checkouts = []
        for index, raw_step in enumerate(steps):
            step = mapping(raw_step, f"{path}.jobs.{job_id}.steps[{index}]")
            uses = step.get("uses")
            if isinstance(uses, str) and uses.startswith("actions/checkout@"):
                checkouts.append(step)
        if not checkouts:
            fail(f"{path}.jobs.{job_id} has no actions/checkout step")
        for step in checkouts:
            with_values = mapping(
                step.get("with"), f"{path}.jobs.{job_id} checkout.with"
            )
            if with_values.get("ref") != CHECKOUT_REF:
                fail(
                    f"{path}.jobs.{job_id} checkout ref must be {CHECKOUT_REF!r}"
                )
            if with_values.get("persist-credentials") != "false":
                fail(f"{path}.jobs.{job_id} checkout must disable persisted credentials")


def validate_reusable_workflow(path: Path) -> dict[str, Any]:
    workflow = load_workflow(path)
    workflow_call_input(workflow, path)
    checkout_steps(workflow, path)
    return workflow


def require_runner(
    job: dict[str, Any], expected: Any, context: str, key: str = "runs-on"
) -> None:
    if job.get(key) != expected:
        fail(f"{context}.{key} must be {expected!r}")


def validate_runner_policy(workflows: dict[str, dict[str, Any]]) -> None:
    """Keep Linux work on Runnit's labeled organization runners.

    The organization currently exposes Linux self-hosted runners only.  The
    macOS rows remain explicit self-hosted platform requirements so this check
    cannot accidentally turn an unavailable macOS lane into a Linux success.
    """

    ci = workflows["ci.yml"]
    ci_jobs = mapping(ci["jobs"], "ci.yml.jobs")
    quality = mapping(ci_jobs["quality"], "ci.yml.jobs.quality")
    if "strategy" in quality:
        fail("ci.yml.jobs.quality must be the single Linux quality job")
    require_runner(quality, RUNNIT_LINUX_LABELS, "ci.yml.jobs.quality")
    quality_macos = mapping(ci_jobs.get("quality-macos"), "ci.yml.jobs.quality-macos")
    if quality_macos.get("if") != "${{ inputs.include-macos }}":
        fail("ci.yml.jobs.quality-macos must be gated by inputs.include-macos")
    require_runner(
        quality_macos,
        RUNNIT_MACOS_X64_LABELS,
        "ci.yml.jobs.quality-macos",
    )
    for job_id in ("fixtures-and-properties", "supply-chain"):
        require_runner(ci_jobs[job_id], RUNNIT_LINUX_LABELS, f"ci.yml.jobs.{job_id}")

    hardening = workflows["hardening.yml"]
    hardening_jobs = mapping(hardening["jobs"], "hardening.yml.jobs")
    for job_id, raw_job in hardening_jobs.items():
        require_runner(
            mapping(raw_job, f"hardening.yml.jobs.{job_id}"),
            RUNNIT_LINUX_LABELS,
            f"hardening.yml.jobs.{job_id}",
        )

    secret_scan = workflows["secret-scan.yml"]
    secret_jobs = mapping(secret_scan["jobs"], "secret-scan.yml.jobs")
    require_runner(secret_jobs["gitleaks"], RUNNIT_LINUX_LABELS, "secret-scan.yml.jobs.gitleaks")

    release = workflows["release.yml"]
    release_jobs = mapping(release["jobs"], "release.yml.jobs")
    for job_id in ("resolve", "gates", "assemble", "publish"):
        require_runner(release_jobs[job_id], RUNNIT_LINUX_LABELS, f"release.yml.jobs.{job_id}")

    build = mapping(release_jobs["build"], "release.yml.jobs.build")
    if build.get("runs-on") != "${{ matrix.runner }}":
        fail("release.yml.jobs.build.runs-on must use matrix.runner")
    build_strategy = mapping(build.get("strategy"), "release.yml.jobs.build.strategy")
    build_matrix = mapping(build_strategy.get("matrix"), "release.yml.jobs.build.strategy.matrix")
    build_include = sequence(
        build_matrix.get("include"), "release.yml.jobs.build.strategy.matrix.include"
    )
    expected_build_runners = {
        "x86_64-unknown-linux-gnu": RUNNIT_LINUX_LABELS,
        "aarch64-unknown-linux-gnu": RUNNIT_LINUX_LABELS,
        "x86_64-apple-darwin": RUNNIT_MACOS_X64_LABELS,
        "aarch64-apple-darwin": RUNNIT_MACOS_ARM64_LABELS,
    }
    seen_targets: set[str] = set()
    for index, raw_row in enumerate(build_include):
        row = mapping(raw_row, f"release.yml.jobs.build.strategy.matrix.include[{index}]")
        target = required_string(
            row, "target", f"release.yml.jobs.build.strategy.matrix.include[{index}]"
        )
        if target in seen_targets:
            fail(f"release.yml build matrix duplicates target {target!r}")
        seen_targets.add(target)
        if target not in expected_build_runners:
            fail(f"release.yml build matrix has unexpected target {target!r}")
        require_runner(
            row,
            expected_build_runners[target],
            f"release.yml build matrix row {target}",
            key="runner",
        )
    if seen_targets != set(expected_build_runners):
        fail("release.yml build matrix must retain all Linux and macOS release targets")


def run_contents(job: dict[str, Any], context: str) -> str:
    steps = sequence(job.get("steps"), f"{context}.steps")
    runs = [step["run"] for step in steps if isinstance(step, dict) and "run" in step]
    if not all(isinstance(run, str) for run in runs):
        fail(f"{context}.steps run values must be strings")
    return "\n".join(
        line
        for run in runs
        for line in run.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def find_step(job: dict[str, Any], predicate: Any, context: str) -> dict[str, Any]:
    steps = sequence(job.get("steps"), f"{context}.steps")
    for index, raw_step in enumerate(steps):
        step = mapping(raw_step, f"{context}.steps[{index}]")
        if predicate(step):
            return step
    fail(f"{context} is missing the required step")


def validate_release(path: Path, workflows: dict[str, dict[str, Any]]) -> None:
    release = load_workflow(path)
    jobs = mapping(release["jobs"], f"{path}.jobs")
    missing = REQUIRED_RELEASE_JOBS - set(jobs)
    if missing:
        fail(f"{path}.jobs is missing required jobs: {', '.join(sorted(missing))}")

    resolve = mapping(jobs["resolve"], f"{path}.jobs.resolve")
    source_step = find_step(
        resolve,
        lambda step: step.get("id") == "source",
        f"{path}.jobs.resolve",
    )
    source_run = source_step.get("run")
    if not isinstance(source_run, str):
        fail(f"{path}.jobs.resolve source step must have a run script")
    source_run = "\n".join(
        line
        for line in source_run.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    for command in (
        'git show-ref --tags --verify --quiet "refs/tags/$RELEASE_TAG"',
        'checkout_sha="$(git rev-parse --verify HEAD^{commit})"',
        'tag_sha="$(git rev-parse --verify "$RELEASE_TAG^{commit}")"',
        'test "$checkout_sha" = "$tag_sha"',
    ):
        if command not in source_run:
            fail(f"{path}.jobs.resolve source step is missing: {command}")
    outputs = mapping(resolve.get("outputs"), f"{path}.jobs.resolve.outputs")
    if outputs.get("tag") != "${{ steps.source.outputs.tag }}":
        fail(f"{path}.jobs.resolve must expose the resolved tag")
    if outputs.get("sha") != "${{ steps.source.outputs.sha }}":
        fail(f"{path}.jobs.resolve must expose the resolved SHA")

    resolve_checkout = find_step(
        resolve,
        lambda step: isinstance(step.get("uses"), str)
        and step["uses"].startswith("actions/checkout@"),
        f"{path}.jobs.resolve",
    )
    resolve_with = mapping(resolve_checkout.get("with"), f"{path}.jobs.resolve checkout.with")
    if resolve_with.get("ref") != RELEASE_TAG_REF:
        fail(f"{path}.jobs.resolve must check out the requested tag/ref")
    if resolve_with.get("persist-credentials") != "false":
        fail(f"{path}.jobs.resolve checkout must disable persisted credentials")

    expected_calls = {
        "ci": "./.github/workflows/ci.yml",
        "hardening": "./.github/workflows/hardening.yml",
        "secret_scan": "./.github/workflows/secret-scan.yml",
    }
    for job_id, expected_workflow in expected_calls.items():
        job = mapping(jobs[job_id], f"{path}.jobs.{job_id}")
        if job.get("uses") != expected_workflow:
            fail(f"{path}.jobs.{job_id} must call {expected_workflow}")
        if needs_set(job, job_id) != {"resolve"}:
            fail(f"{path}.jobs.{job_id} must depend directly on resolve")
        with_values = mapping(job.get("with"), f"{path}.jobs.{job_id}.with")
        if with_values.get("checkout-ref") != RELEASE_SHA:
            fail(f"{path}.jobs.{job_id} must pass the resolved SHA")
        if job_id == "ci" and with_values.get("include-macos") != "true":
            fail(f"{path}.jobs.ci must opt into the gated macOS quality job")
        if job_id != "ci" and "include-macos" in with_values:
            fail(f"{path}.jobs.{job_id} must not pass include-macos")

    if needs_set(mapping(jobs["gates"], f"{path}.jobs.gates"), "gates") != {"resolve"}:
        fail(f"{path}.jobs.gates must depend directly on resolve")
    if needs_set(mapping(jobs["build"], f"{path}.jobs.build"), "build") != {"resolve"}:
        fail(f"{path}.jobs.build must depend directly on resolve")

    for job_id in ("gates", "build", "assemble"):
        job = mapping(jobs[job_id], f"{path}.jobs.{job_id}")
        checkout = find_step(
            job,
            lambda step: isinstance(step.get("uses"), str)
            and step["uses"].startswith("actions/checkout@"),
            f"{path}.jobs.{job_id}",
        )
        with_values = mapping(checkout.get("with"), f"{path}.jobs.{job_id} checkout.with")
        if with_values.get("ref") != RELEASE_SHA:
            fail(f"{path}.jobs.{job_id} must check out the resolved SHA")
        if with_values.get("persist-credentials") != "false":
            fail(f"{path}.jobs.{job_id} checkout must disable persisted credentials")

    required_upstream = {"resolve", "build", "gates", "ci", "hardening", "secret_scan"}
    if needs_set(mapping(jobs["assemble"], f"{path}.jobs.assemble"), "assemble") != required_upstream:
        fail("release assemble must depend on build, local gates, and all required acceptance workflows")
    required_publish = {"resolve", "assemble", "gates", "ci", "hardening", "secret_scan"}
    if needs_set(mapping(jobs["publish"], f"{path}.jobs.publish"), "publish") != required_publish:
        fail("release publish must depend on assemble, local gates, and all required acceptance workflows")

    hardening_jobs = mapping(workflows["hardening.yml"]["jobs"], "hardening.yml.jobs")
    for job_id in ("fuzz", "sanitizer"):
        if job_id not in hardening_jobs:
            fail(f"hardening.yml must define the {job_id} job")
    secret_jobs = mapping(workflows["secret-scan.yml"]["jobs"], "secret-scan.yml.jobs")
    if "gitleaks" not in secret_jobs:
        fail("secret-scan.yml must define the gitleaks job")

    # Keep this helper explicit: it ensures the release-local gate still runs
    # executable checks, rather than merely carrying job labels.
    if "scripts/deep-test.sh" not in run_contents(hardening_jobs["fuzz"], "hardening.yml.jobs.fuzz"):
        fail("hardening.yml fuzz job must run scripts/deep-test.sh")
    if "scripts/deep-test.sh" not in run_contents(
        hardening_jobs["sanitizer"], "hardening.yml.jobs.sanitizer"
    ):
        fail("hardening.yml sanitizer job must run scripts/deep-test.sh")
    gitleaks_step = find_step(
        secret_jobs["gitleaks"],
        lambda step: isinstance(step.get("uses"), str)
        and step["uses"].startswith("gitleaks/gitleaks-action@"),
        "secret-scan.yml.jobs.gitleaks",
    )
    if not isinstance(gitleaks_step.get("env"), dict) or "GITLEAKS_CONFIG" not in gitleaks_step["env"]:
        fail("secret-scan.yml gitleaks job must use the repository configuration")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (used by isolated structural tests)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    workflow_root = root / ".github" / "workflows"
    paths = {
        name: workflow_root / name
        for name in ("ci.yml", "hardening.yml", "secret-scan.yml", "release.yml")
    }
    for path in paths.values():
        if not path.is_file():
            fail(f"missing workflow: {path}")
    reusable = {
        name: validate_reusable_workflow(path)
        for name, path in paths.items()
        if name != "release.yml"
    }
    release = load_workflow(paths["release.yml"])
    workflows = {**reusable, "release.yml": release}
    validate_runner_policy(workflows)
    validate_release(paths["release.yml"], reusable)
    print("release workflow dependency checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"release workflow check: {error}", file=sys.stderr)
        raise SystemExit(1) from error
