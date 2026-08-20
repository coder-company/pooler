#!/usr/bin/env python3
"""Render deterministic CycloneDX 1.5 and SPDX 2.3 cargo SBOMs."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any
import uuid


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument("--cyclonedx", type=Path, required=True)
    parser.add_argument("--spdx", type=Path, required=True)
    return parser.parse_args()


def package_key(package: dict[str, Any]) -> str:
    source = package.get("source") or "workspace"
    return f"{package['name']}@{package['version']}|{source}"


def component_ref(package: dict[str, Any]) -> str:
    digest = hashlib.sha256(package_key(package).encode("utf-8")).hexdigest()[:24]
    return f"pkg:cargo/{package['name']}@{package['version']}#{digest}"


def spdx_id(package: dict[str, Any]) -> str:
    digest = hashlib.sha256(package_key(package).encode("utf-8")).hexdigest()[:24]
    return f"SPDXRef-Package-{digest}"


def license_entries(package: dict[str, Any]) -> list[dict[str, Any]]:
    license_expression = package.get("license")
    if not license_expression:
        return []
    return [{"license": {"id": license_expression}}]


def repository_reference(package: dict[str, Any]) -> dict[str, str] | None:
    repository = package.get("repository")
    if not repository:
        return None
    return {
        "type": "website",
        "url": repository,
    }


def cargo_download_location(package: dict[str, Any]) -> str:
    if package.get("source"):
        return f"https://crates.io/crates/{package['name']}/{package['version']}"
    return package.get("repository") or "NOASSERTION"


def read_packages(metadata_path: Path) -> list[dict[str, Any]]:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise ValueError("cargo metadata did not contain a package list")
    return sorted(packages, key=lambda package: package_key(package))


def dependency_refs(
    package: dict[str, Any],
    refs_by_name: dict[str, list[str]],
) -> list[str]:
    refs: set[str] = set()
    for dependency in package.get("dependencies", []):
        refs.update(refs_by_name.get(dependency["name"], []))
    return sorted(refs)


def render_cyclonedx(packages: list[dict[str, Any]], version: str, epoch: int) -> dict[str, Any]:
    refs_by_name: dict[str, list[str]] = {}
    for package in packages:
        refs_by_name.setdefault(package["name"], []).append(component_ref(package))
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
        repository = repository_reference(package)
        if repository:
            component["externalReferences"] = [repository]
        components.append(component)
        dependencies.append(
            {
                "ref": reference,
                "dependsOn": dependency_refs(package, refs_by_name),
            }
        )

    root_ref = f"pkg:generic/pooler@{version}"
    cli_refs = refs_by_name.get("pooler-cli", [])
    bom_namespace = f"https://github.com/coder-company/pooler/releases/sbom/{version}"
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
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
        },
        "components": components,
        "dependencies": [{"ref": root_ref, "dependsOn": cli_refs}, *dependencies],
    }


def render_spdx(packages: list[dict[str, Any]], version: str, epoch: int) -> dict[str, Any]:
    refs_by_name: dict[str, list[str]] = {}
    for package in packages:
        refs_by_name.setdefault(package["name"], []).append(spdx_id(package))

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
        expression = package.get("license") or "NOASSERTION"
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
        for dependency_id in dependency_refs(package, refs_by_name):
            relationships.append(
                {
                    "spdxElementId": package_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": dependency_id,
                }
            )
    cli_ids = refs_by_name.get("pooler-cli", [])
    for cli_id in cli_ids:
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": cli_id,
            }
        )

    namespace = f"https://github.com/coder-company/pooler/releases/sbom/{version}/spdx"
    created = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
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
    packages = read_packages(arguments.metadata)
    write_json(
        arguments.cyclonedx,
        render_cyclonedx(packages, arguments.version, arguments.epoch),
    )
    write_json(arguments.spdx, render_spdx(packages, arguments.version, arguments.epoch))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
