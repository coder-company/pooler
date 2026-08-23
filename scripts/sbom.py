#!/usr/bin/env python3
"""Render deterministic CycloneDX 1.5 and SPDX 2.3 release SBOMs."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tomllib
from typing import Any
import uuid


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ASSETS_MANIFEST = (
    REPOSITORY_ROOT / "third-party" / "dashboard-assets" / "manifest.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument(
        "--target",
        help="target identity used to distinguish platform-specific SBOM documents",
    )
    parser.add_argument(
        "--assets-manifest",
        type=Path,
        default=DEFAULT_ASSETS_MANIFEST,
        help="manifest of non-Cargo components embedded in the dashboard",
    )
    parser.add_argument("--cyclonedx", type=Path, required=True)
    parser.add_argument("--spdx", type=Path, required=True)
    return parser.parse_args()


def package_key(package: dict[str, Any]) -> str:
    source = package.get("source") or "workspace"
    return f"{package['name']}@{package['version']}|{source}"


def package_identity(package: dict[str, Any]) -> str:
    """Return Cargo's package ID, falling back for hand-written fixtures.

    Cargo package names are not unique in a metadata graph: a lockfile may
    contain several versions of a crate, and a workspace can contain two
    path packages with the same name and version. The package ID is the
    identity used by ``resolve.nodes`` and must therefore be preferred for
    dependency edges and component lookup.
    """

    identifier = package.get("id")
    if isinstance(identifier, str) and identifier:
        return identifier
    return package_key(package)


def package_sort_key(package: dict[str, Any]) -> tuple[str, str]:
    return package_key(package), package_identity(package)


def component_ref(package: dict[str, Any]) -> str:
    # Cargo path package IDs contain the absolute checkout path. Keep those
    # paths out of published refs so local and hosted builds are identical;
    # package IDs are still used internally for graph edges.
    digest = hashlib.sha256(package_key(package).encode("utf-8")).hexdigest()[:24]
    return f"pkg:cargo/{package['name']}@{package['version']}#{digest}"


def spdx_id(package: dict[str, Any]) -> str:
    digest = hashlib.sha256(package_key(package).encode("utf-8")).hexdigest()[:24]
    return f"SPDXRef-Package-{digest}"


def normalize_license_expression(value: object) -> str | None:
    """Normalize the two legacy Cargo slash spellings we have encountered."""

    if not isinstance(value, str):
        return None
    expression = " ".join(value.strip().split())
    if not expression or expression == "NOASSERTION":
        return None

    # ``/`` was used by old Cargo metadata as a permissive separator for
    # these two licenses. It means OR here; preserving operand order keeps
    # the licensing semantics explicit without guessing about other strings.
    return {
        "MIT/Apache-2.0": "MIT OR Apache-2.0",
        "MIT / Apache-2.0": "MIT OR Apache-2.0",
        "Apache-2.0/MIT": "Apache-2.0 OR MIT",
        "Apache-2.0 / MIT": "Apache-2.0 OR MIT",
    }.get(expression, expression)


def license_entries(package: dict[str, Any]) -> list[dict[str, Any]]:
    license_expression = normalize_license_expression(package.get("license"))
    if license_expression is None:
        return []
    # Cargo's license field is an SPDX expression, even when it contains a
    # single identifier. CycloneDX's licenseChoice places the expression at
    # the choice level; nesting it under a ``license`` object is invalid.
    return [{"expression": license_expression}]


def repository_reference(package: dict[str, Any]) -> dict[str, str] | None:
    repository = package.get("repository")
    if not repository:
        return None
    return {"type": "website", "url": repository}


def cargo_download_location(package: dict[str, Any]) -> str:
    if package.get("source"):
        return f"https://crates.io/crates/{package['name']}/{package['version']}"
    return package.get("repository") or "NOASSERTION"


def _read_metadata(metadata_path: Path) -> dict[str, Any]:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError("cargo metadata must be a JSON object")
    return metadata


def _valid_checksum(value: object) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return None
    return value.lower()


def _lockfile_checksums(workspace_root: object) -> dict[tuple[str, str, str], str]:
    """Read registry checksums from Cargo.lock when that lockfile is present."""

    if not isinstance(workspace_root, str) or not workspace_root:
        return {}
    lockfile = Path(workspace_root) / "Cargo.lock"
    try:
        lock = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}

    checksums: dict[tuple[str, str, str], str] = {}
    for entry in lock.get("package", []):
        if not isinstance(entry, dict):
            continue
        checksum = _valid_checksum(entry.get("checksum"))
        source = entry.get("source")
        if (
            checksum
            and isinstance(entry.get("name"), str)
            and isinstance(entry.get("version"), str)
            and isinstance(source, str)
        ):
            checksums[(entry["name"], entry["version"], source)] = checksum
    return checksums


def _attach_checksums(metadata: dict[str, Any], packages: list[dict[str, Any]]) -> None:
    checksums = _lockfile_checksums(metadata.get("workspace_root"))
    for package in packages:
        checksum = _valid_checksum(package.get("checksum"))
        if checksum is None and isinstance(package.get("source"), str):
            checksum = checksums.get(
                (package.get("name", ""), package.get("version", ""), package["source"])
            )
        if checksum is not None:
            package["checksum"] = checksum


def _runtime_dependency_graph(
    metadata: dict[str, Any], packages: list[dict[str, Any]]
) -> dict[str, list[str]]:
    """Build normal-dependency edges using Cargo resolve package IDs.

    ``resolve.nodes[*].deps`` carries the selected package ID and dependency
    kinds. Keeping only normal (``kind == null``) edges removes test/dev
    dependencies from a release SBOM while retaining target-specific runtime
    dependencies selected by Cargo's ``--filter-platform`` invocation.
    """

    package_ids = {package_identity(package) for package in packages}
    resolve = metadata.get("resolve")
    nodes = resolve.get("nodes") if isinstance(resolve, dict) else None
    graph: dict[str, list[str]] = {}
    if isinstance(nodes, list):
        for node in nodes:
            if not isinstance(node, dict):
                continue
            identifier = node.get("id")
            if not isinstance(identifier, str) or identifier not in package_ids:
                continue
            dependencies: set[str] = set()
            for dependency in node.get("deps", []):
                if isinstance(dependency, str):
                    dependency_id = dependency
                    dependency_kinds: list[dict[str, Any]] = []
                elif isinstance(dependency, dict):
                    dependency_id = dependency.get("pkg")
                    raw_kinds = dependency.get("dep_kinds", [])
                    dependency_kinds = raw_kinds if isinstance(raw_kinds, list) else []
                else:
                    continue
                if not isinstance(dependency_id, str) or dependency_id not in package_ids:
                    continue
                if dependency_kinds and not any(
                    isinstance(kind, dict) and kind.get("kind") in (None, "normal")
                    for kind in dependency_kinds
                ):
                    continue
                dependencies.add(dependency_id)
            graph[identifier] = sorted(dependencies)

    # Small metadata fixtures and older Cargo metadata versions may omit
    # ``resolve.nodes``. Fall back to exact (name, source) matches only when
    # they are unambiguous; guessing between selected versions is unsafe.
    packages_by_name_source: dict[tuple[str, object], list[str]] = {}
    for package in packages:
        packages_by_name_source.setdefault(
            (package["name"], package.get("source")), []
        ).append(package_identity(package))
    for package in packages:
        identifier = package_identity(package)
        if identifier in graph:
            continue
        dependencies: set[str] = set()
        for dependency in package.get("dependencies", []):
            if not isinstance(dependency, dict) or dependency.get("kind") not in (
                None,
                "",
                "normal",
            ):
                continue
            name = dependency.get("name")
            if not isinstance(name, str):
                continue
            source = dependency.get("source")
            candidates = packages_by_name_source.get((name, source), [])
            if len(candidates) == 1:
                dependencies.add(candidates[0])
        graph[identifier] = sorted(dependencies)
    return graph


def _runtime_closure(
    packages: list[dict[str, Any]], graph: dict[str, list[str]]
) -> set[str]:
    roots = [
        package_identity(package)
        for package in packages
        if package.get("name") == "pooler-cli"
    ]
    if len(roots) != 1:
        return {package_identity(package) for package in packages}

    closure: set[str] = set()
    pending = roots[:]
    while pending:
        identifier = pending.pop()
        if identifier in closure:
            continue
        closure.add(identifier)
        pending.extend(graph.get(identifier, []))
    return closure


def read_release_metadata(
    metadata_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, list[str]], str | None]:
    """Read metadata and select the pooler-cli normal-dependency closure."""

    metadata = _read_metadata(metadata_path)
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise ValueError("cargo metadata did not contain a package list")
    if not all(isinstance(package, dict) for package in packages):
        raise ValueError("cargo metadata package entries must be objects")
    _attach_checksums(metadata, packages)
    graph = _runtime_dependency_graph(metadata, packages)
    closure = _runtime_closure(packages, graph)
    selected = [package for package in packages if package_identity(package) in closure]
    selected.sort(key=package_sort_key)
    cli_ids = [
        package_identity(package)
        for package in selected
        if package.get("name") == "pooler-cli"
    ]
    return selected, graph, cli_ids[0] if len(cli_ids) == 1 else None


def read_packages(metadata_path: Path) -> list[dict[str, Any]]:
    """Read all metadata packages (legacy helper retained for callers/tests)."""

    metadata = _read_metadata(metadata_path)
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise ValueError("cargo metadata did not contain a package list")
    if not all(isinstance(package, dict) for package in packages):
        raise ValueError("cargo metadata package entries must be objects")
    _attach_checksums(metadata, packages)
    return sorted(packages, key=package_sort_key)


def read_embedded_components(manifest_path: Path) -> list[dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("dashboard asset manifest must use schema_version 1")
    components = manifest.get("components")
    if not isinstance(components, list):
        raise ValueError("dashboard asset manifest did not contain a component list")

    seen: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("dashboard asset manifest components must be objects")
        identifier = component.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("dashboard asset manifest component id must be a string")
        if identifier in seen:
            raise ValueError(f"duplicate dashboard asset component id: {identifier}")
        seen.add(identifier)
        if not isinstance(component.get("name"), str):
            raise ValueError(f"dashboard asset component {identifier} has no name")
        if component.get("sbom_type") not in {"file", "library"}:
            raise ValueError(
                f"dashboard asset component {identifier} has an invalid sbom_type"
            )
        if not isinstance(component.get("license_expression"), str):
            raise ValueError(
                f"dashboard asset component {identifier} has no license_expression"
            )
        if not isinstance(component.get("source"), dict):
            raise ValueError(f"dashboard asset component {identifier} has no source")
        if not isinstance(component.get("embedded_assets"), list):
            raise ValueError(
                f"dashboard asset component {identifier} has no embedded_assets list"
            )
    return sorted(components, key=lambda component: component["id"])


def embedded_component_ref(component: dict[str, Any]) -> str:
    return f"urn:pooler:embedded-dashboard-asset:{component['id']}"


def embedded_spdx_id(component: dict[str, Any]) -> str:
    digest = hashlib.sha256(component["id"].encode("utf-8")).hexdigest()[:24]
    return f"SPDXRef-Embedded-{digest}"


def embedded_license_entries(component: dict[str, Any]) -> list[dict[str, Any]]:
    expression = normalize_license_expression(component.get("license_expression"))
    if expression is None:
        return []
    return [{"expression": expression}]


def embedded_comment(component: dict[str, Any]) -> str:
    details = [component.get("version_evidence", "")]
    if component.get("embedded_subset"):
        details.append(component["embedded_subset"])
    if component.get("transform"):
        details.append(component["transform"])
    assets = ", ".join(component["embedded_assets"])
    details.append(f"Embedded assets: {assets}")
    return " ".join(detail.strip() for detail in details if detail).strip()


def dependency_refs(
    package: dict[str, Any],
    refs_by_name: dict[str, list[str]],
    *,
    refs_by_id: dict[str, str] | None = None,
    dependency_graph: dict[str, list[str]] | None = None,
) -> list[str]:
    if dependency_graph is not None and refs_by_id is not None:
        return sorted(
            refs_by_id[dependency_id]
            for dependency_id in dependency_graph.get(package_identity(package), [])
            if dependency_id in refs_by_id
        )

    refs: set[str] = set()
    for dependency in package.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue
        dependency_id = dependency.get("id") or dependency.get("package")
        if refs_by_id is not None and isinstance(dependency_id, str):
            reference = refs_by_id.get(dependency_id)
            if reference:
                refs.add(reference)
                continue
        name = dependency.get("name")
        if isinstance(name, str):
            refs.update(refs_by_name.get(name, []))
    return sorted(refs)


def render_cyclonedx(
    packages: list[dict[str, Any]],
    version: str,
    epoch: int,
    embedded_components: list[dict[str, Any]] | None = None,
    dependency_graph: dict[str, list[str]] | None = None,
    root_package_id: str | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    refs_by_name: dict[str, list[str]] = {}
    refs_by_id: dict[str, str] = {}
    for package in packages:
        reference = component_ref(package)
        refs_by_name.setdefault(package["name"], []).append(reference)
        refs_by_id[package_identity(package)] = reference

    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    for package in packages:
        reference = component_ref(package)
        component: dict[str, Any] = {
            "bom-ref": reference,
            "name": package["name"],
            "type": "library",
            "version": package["version"],
            "purl": f"pkg:cargo/{package['name']}@{package['version']}",
        }
        licenses = license_entries(package)
        if licenses:
            component["licenses"] = licenses
        checksum = _valid_checksum(package.get("checksum"))
        if checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        repository = repository_reference(package)
        if repository:
            component["externalReferences"] = [repository]
        components.append(component)
        dependencies.append(
            {
                "ref": reference,
                "dependsOn": dependency_refs(
                    package,
                    refs_by_name,
                    refs_by_id=refs_by_id,
                    dependency_graph=dependency_graph,
                ),
            }
        )

    embedded_refs: list[str] = []
    for embedded in embedded_components or []:
        reference = embedded_component_ref(embedded)
        embedded_refs.append(reference)
        component: dict[str, Any] = {
            "bom-ref": reference,
            "name": embedded["name"],
            "type": embedded.get("sbom_type", "file"),
            "properties": [
                {
                    "name": "pooler:embedded-assets",
                    "value": ",".join(embedded["embedded_assets"]),
                },
                {
                    "name": "pooler:provenance",
                    "value": embedded_comment(embedded),
                },
            ],
        }
        if embedded.get("version"):
            component["version"] = embedded["version"]
        licenses = embedded_license_entries(embedded)
        if licenses:
            component["licenses"] = licenses
        source_url = embedded.get("source", {}).get("url")
        if source_url:
            component["externalReferences"] = [
                {"type": "distribution", "url": source_url}
            ]
        components.append(component)
        dependencies.append({"ref": reference, "dependsOn": []})

    root_ref = f"pkg:generic/pooler@{version}"
    cli_refs = refs_by_name.get("pooler-cli", [])
    cli_ref = refs_by_id.get(root_package_id) if root_package_id else None
    root_dependencies = ([cli_ref] if cli_ref else cli_refs) + embedded_refs
    target_identity = target or "unqualified"
    bom_namespace = (
        f"https://github.com/coder-company/pooler/releases/sbom/"
        f"{version}/{target_identity}"
    )
    serial = uuid.uuid5(uuid.NAMESPACE_URL, bom_namespace)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.fromtimestamp(epoch, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "tools": [
                {
                    "vendor": "Pooler",
                    "name": "pooler-release",
                    "version": version,
                }
            ],
            "component": {
                "bom-ref": root_ref,
                "name": "pooler",
                "publisher": "Pooler contributors",
                "type": "application",
                "version": version,
                "licenses": [{"expression": "Apache-2.0"}],
            },
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": sorted(root_dependencies)},
            *dependencies,
        ],
    }


def render_spdx(
    packages: list[dict[str, Any]],
    version: str,
    epoch: int,
    embedded_components: list[dict[str, Any]] | None = None,
    dependency_graph: dict[str, list[str]] | None = None,
    root_package_id: str | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    refs_by_name: dict[str, list[str]] = {}
    refs_by_id: dict[str, str] = {}
    for package in packages:
        reference = spdx_id(package)
        refs_by_name.setdefault(package["name"], []).append(reference)
        refs_by_id[package_identity(package)] = reference

    root_id = "SPDXRef-Package-pooler"
    spdx_packages: list[dict[str, Any]] = [
        {
            "SPDXID": root_id,
            "name": "pooler",
            "versionInfo": version,
            "downloadLocation": "https://github.com/coder-company/pooler",
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "filesAnalyzed": False,
            "copyrightText": "NOASSERTION",
        }
    ]
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    for package in packages:
        package_id = spdx_id(package)
        expression = normalize_license_expression(package.get("license")) or "NOASSERTION"
        spdx_packages.append(
            {
                "SPDXID": package_id,
                "name": package["name"],
                "versionInfo": package["version"],
                "downloadLocation": cargo_download_location(package),
                "licenseConcluded": expression,
                "licenseDeclared": expression,
                "filesAnalyzed": False,
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:cargo/{package['name']}@{package['version']}",
                    }
                ],
            }
        )
        checksum = _valid_checksum(package.get("checksum"))
        if checksum:
            spdx_packages[-1]["checksums"] = [
                {"algorithm": "SHA256", "checksumValue": checksum}
            ]
        for dependency_id in dependency_refs(
            package,
            refs_by_name,
            refs_by_id=refs_by_id,
            dependency_graph=dependency_graph,
        ):
            relationships.append(
                {
                    "spdxElementId": package_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": dependency_id,
                }
            )
    cli_ids = (
        [refs_by_id[root_package_id]]
        if root_package_id in refs_by_id
        else refs_by_name.get("pooler-cli", [])
    )
    for cli_id in cli_ids:
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": cli_id,
            }
        )

    for embedded in embedded_components or []:
        package_id = embedded_spdx_id(embedded)
        expression = (
            normalize_license_expression(embedded.get("license_expression"))
            or "NOASSERTION"
        )
        source_url = embedded.get("source", {}).get("url") or "NOASSERTION"
        package: dict[str, Any] = {
            "SPDXID": package_id,
            "name": embedded["name"],
            "downloadLocation": source_url,
            "licenseConcluded": expression,
            "licenseDeclared": expression,
            "filesAnalyzed": False,
            "copyrightText": embedded.get("copyright_text") or "NOASSERTION",
            "comment": embedded_comment(embedded),
        }
        if embedded.get("version"):
            package["versionInfo"] = embedded["version"]
        spdx_packages.append(package)
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )

    target_identity = target or "unqualified"
    namespace = (
        f"https://github.com/coder-company/pooler/releases/sbom/"
        f"{version}/{target_identity}/spdx"
    )
    created = (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"pooler-{version}",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": created,
            "creators": ["Tool: pooler-release"],
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }


def write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    arguments = parse_args()
    if arguments.epoch < 0:
        raise ValueError("SBOM epoch must not be negative")
    packages, dependency_graph, root_package_id = read_release_metadata(
        arguments.metadata
    )
    embedded_components = read_embedded_components(arguments.assets_manifest)
    write_json(
        arguments.cyclonedx,
        render_cyclonedx(
            packages,
            arguments.version,
            arguments.epoch,
            embedded_components,
            dependency_graph,
            root_package_id,
            arguments.target,
        ),
    )
    write_json(
        arguments.spdx,
        render_spdx(
            packages,
            arguments.version,
            arguments.epoch,
            embedded_components,
            dependency_graph,
            root_package_id,
            arguments.target,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
