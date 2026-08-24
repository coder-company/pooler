#!/usr/bin/env python3
"""Focused checks for dashboard asset release provenance and SBOM rendering."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "third-party" / "dashboard-assets" / "manifest.json"
SBOM_PATH = ROOT / "scripts" / "sbom.py"
ASSET_STAGER = ROOT / "scripts" / "stage-release-assets.sh"
SPEC = importlib.util.spec_from_file_location("pooler_sbom", SBOM_PATH)
assert SPEC is not None and SPEC.loader is not None
SBOM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SBOM)


class DashboardAssetProvenanceTests(unittest.TestCase):
    def test_manifest_inventory_and_license_files_are_complete(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        components = {
            component["id"]: component for component in manifest["components"]
        }
        self.assertEqual(
            set(components),
            {
                "iconoir",
                "lobehub-icons",
                "simple-icons",
                "geist",
                "geist-mono",
                "coder-company-marks",
            },
        )

        inventoried_assets: set[str] = set()
        for component in components.values():
            for asset in component["embedded_assets"]:
                self.assertTrue((ROOT / asset).is_file(), asset)
                inventoried_assets.add(asset)
            license_file = component["license_file"]
            if license_file is not None:
                path = MANIFEST.parent / license_file
                self.assertTrue(path.is_file(), str(path))
                self.assertGreater(path.stat().st_size, 500)

        expected_assets = {
            str(path.relative_to(ROOT))
            for directory in (
                ROOT / "crates" / "pooler-server" / "ui" / "assets",
                ROOT / "crates" / "pooler-server" / "ui" / "fonts",
            )
            for path in directory.iterdir()
            if path.is_file()
        }
        expected_assets.update(
            {
                "crates/pooler-server/ui/icons.js",
                "crates/pooler-server/ui/providers.js",
            }
        )
        self.assertEqual(inventoried_assets, expected_assets)
        self.assertIsNone(components["coder-company-marks"]["version"])
        self.assertEqual(
            components["coder-company-marks"]["license_expression"], "NOASSERTION"
        )
        self.assertIsNone(components["coder-company-marks"]["source"]["url"])

    def test_provider_extractor_inputs_and_inventory_are_pinned(self) -> None:
        extractor = (
            ROOT / "scripts" / "extract-lobehub-icons.mjs"
        ).read_text(encoding="utf-8")
        for pinned in (
            '"@lobehub/icons": "5.16.0"',
            '"es-toolkit": "1.51.0"',
            'react: "19.2.8"',
            '"react-dom": "19.2.8"',
            "const EXPECTED_ICON_COUNT = 319",
            "0cf5f4673a80639ee5f37f2d741cfdad5524e0a3afd77d3a2601685137544bdd",
        ):
            self.assertIn(pinned, extractor)
        self.assertNotIn("npm install", extractor)

    def test_non_cargo_components_are_emitted_in_both_sbom_formats(self) -> None:
        embedded = SBOM.read_embedded_components(MANIFEST)
        packages = [
            {
                "name": "pooler-cli",
                "version": "0.1.0",
                "source": None,
                "license": "Apache-2.0",
                "repository": "https://github.com/coder-company/pooler",
                "dependencies": [],
            }
        ]
        cyclonedx = SBOM.render_cyclonedx(packages, "0.1.0", 0, embedded)
        spdx = SBOM.render_spdx(packages, "0.1.0", 0, embedded)

        cdx_by_name = {
            component["name"]: component for component in cyclonedx["components"]
        }
        spdx_by_name = {package["name"]: package for package in spdx["packages"]}
        for name in (
            "Iconoir",
            "LobeHub Icons",
            "Simple Icons",
            "Geist",
            "Geist Mono",
            "Coder Company marks",
        ):
            self.assertIn(name, cdx_by_name)
            self.assertIn(name, spdx_by_name)

        coder_cdx = cdx_by_name["Coder Company marks"]
        self.assertNotIn("version", coder_cdx)
        self.assertNotIn("licenses", coder_cdx)
        coder_spdx = spdx_by_name["Coder Company marks"]
        self.assertNotIn("versionInfo", coder_spdx)
        self.assertEqual(coder_spdx["licenseDeclared"], "NOASSERTION")
        self.assertEqual(coder_spdx["downloadLocation"], "NOASSERTION")
        self.assertEqual(
            cdx_by_name["Iconoir"]["licenses"],
            [{"expression": "MIT"}],
        )
        for component in [
            cyclonedx["metadata"]["component"],
            *cyclonedx["components"],
        ]:
            for choice in component.get("licenses", []):
                self.assertEqual(set(choice), {"expression"})
                self.assertIsInstance(choice["expression"], str)

        root_dependency = next(
            dependency
            for dependency in cyclonedx["dependencies"]
            if dependency["ref"] == "pkg:generic/pooler@0.1.0"
        )
        self.assertEqual(len(root_dependency["dependsOn"]), 7)
        embedded_spdx_ids = {
            package["SPDXID"]
            for package in spdx["packages"]
            if package["name"] in cdx_by_name and package["name"] != "pooler-cli"
        }
        root_relationships = {
            relationship["relatedSpdxElement"]
            for relationship in spdx["relationships"]
            if relationship["spdxElementId"] == "SPDXRef-Package-pooler"
            and relationship["relationshipType"] == "DEPENDS_ON"
        }
        self.assertTrue(embedded_spdx_ids.issubset(root_relationships))

    def test_runtime_closure_uses_resolved_package_ids(self) -> None:
        cli_id = "path+file:///workspace/pooler-cli#pooler-cli@0.1.0"
        runtime_id = "registry+https://example.invalid#index#shared@1.0.0"
        other_version_id = "registry+https://example.invalid#index#shared@2.0.0"
        dev_id = "registry+https://example.invalid#index#dev-only@1.0.0"
        unrelated_id = "registry+https://example.invalid#index#unrelated@1.0.0"

        def package(identifier: str, name: str, version: str) -> dict[str, object]:
            return {
                "id": identifier,
                "name": name,
                "version": version,
                "source": None if identifier.startswith("path+") else "registry+https://example.invalid/index",
                "license": "MIT",
                "dependencies": [],
            }

        metadata = {
            "packages": [
                package(cli_id, "pooler-cli", "0.1.0"),
                package(runtime_id, "shared", "1.0.0"),
                package(other_version_id, "shared", "2.0.0"),
                package(dev_id, "dev-only", "1.0.0"),
                package(unrelated_id, "unrelated", "1.0.0"),
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": cli_id,
                        "deps": [
                            {
                                "pkg": runtime_id,
                                "dep_kinds": [{"kind": None, "target": None}],
                            },
                            {
                                "pkg": dev_id,
                                "dep_kinds": [{"kind": "dev", "target": None}],
                            },
                        ],
                    },
                    {"id": runtime_id, "deps": []},
                    {"id": other_version_id, "deps": []},
                    {"id": dev_id, "deps": []},
                    {"id": unrelated_id, "deps": []},
                ]
            },
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            metadata_path = Path(temporary_directory) / "metadata.json"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            packages, graph, root_id = SBOM.read_release_metadata(metadata_path)

        self.assertEqual(root_id, cli_id)
        self.assertEqual({package["id"] for package in packages}, {cli_id, runtime_id})
        self.assertEqual(graph[cli_id], [runtime_id])
        cyclonedx = SBOM.render_cyclonedx(
            packages, "0.1.0", 0, [], graph, root_id
        )
        cli_component = next(
            component for component in cyclonedx["components"] if component["name"] == "pooler-cli"
        )
        cli_dependency = next(
            dependency
            for dependency in cyclonedx["dependencies"]
            if dependency["ref"] == cli_component["bom-ref"]
        )
        shared_component = next(
            component
            for component in cyclonedx["components"]
            if component["name"] == "shared"
        )
        self.assertEqual(cli_dependency["dependsOn"], [shared_component["bom-ref"]])

    def test_legacy_cargo_license_spellings_are_normalized_semantically(self) -> None:
        self.assertEqual(
            SBOM.normalize_license_expression("MIT/Apache-2.0"),
            "MIT OR Apache-2.0",
        )
        self.assertEqual(
            SBOM.normalize_license_expression("Apache-2.0 / MIT"),
            "Apache-2.0 OR MIT",
        )
        self.assertEqual(
            SBOM.normalize_license_expression("BSD-3-Clause"),
            "BSD-3-Clause",
        )

        for raw, expected in (
            ("MIT/Apache-2.0", "MIT OR Apache-2.0"),
            ("Apache-2.0 / MIT", "Apache-2.0 OR MIT"),
        ):
            package = {
                "name": "legacy-license",
                "version": "1.0.0",
                "source": None,
                "license": raw,
                "dependencies": [],
            }
            cyclonedx = SBOM.render_cyclonedx([package], "1.0.0", 0)
            component = cyclonedx["components"][0]
            self.assertEqual(component["licenses"], [{"expression": expected}])
            spdx = SBOM.render_spdx([package], "1.0.0", 0)
            self.assertEqual(spdx["packages"][1]["licenseDeclared"], expected)

    def test_release_rejects_target_argument_splitting_and_binary_mismatch(self) -> None:
        release = ROOT / "scripts" / "release.sh"
        binary = shutil.which("true")
        self.assertIsNotNone(binary)
        with tempfile.TemporaryDirectory() as temporary_directory:
            split_target = subprocess.run(
                [
                    str(release),
                    "--target",
                    "x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu",
                    "--binary",
                    binary or "true",
                    "--epoch",
                    "0",
                    "--output",
                    temporary_directory,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(split_target.returncode, 2)
            self.assertIn("whitespace", split_target.stderr)

            mismatched_binary = subprocess.run(
                [
                    str(release),
                    "--target",
                    "aarch64-unknown-linux-gnu",
                    "--binary",
                    binary or "true",
                    "--epoch",
                    "0",
                    "--output",
                    temporary_directory,
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(mismatched_binary.returncode, 0)
            self.assertIn("architecture does not match", mismatched_binary.stderr)

    def test_release_asset_stager_copies_runtime_assets_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "root"
            stage = Path(temporary_directory) / "stage"
            (root / "config").mkdir(parents=True)
            (root / "deploy" / "config").mkdir(parents=True)
            (root / "deploy" / "data").mkdir()
            (root / "deploy" / "secrets").mkdir()
            (root / "docs").mkdir()
            (root / "scripts").mkdir()
            (root / "config" / "pooler.example.yaml").write_text("version: 1\n")
            (root / "deploy" / "pooler.example.yaml").write_text("version: 1\n")
            (root / "deploy" / "pooler.service").write_text("[Unit]\n")
            (root / "docs" / "deployment.md").write_text("# Deployment\n")
            for script in (
                "check-deployment-config.py",
                "install-system-pooler.sh",
                "test-system-install.sh",
                "check-staged-secrets.sh",
                "release.sh",
            ):
                (root / "scripts" / script).write_text("# check\n")
            (root / ".dockerignore").write_text("target\n")
            (root / "Dockerfile").write_text("FROM scratch\n")
            (root / "docker-compose.example.yml").write_text("services: {}\n")

            staged = subprocess.run(
                [str(ASSET_STAGER), str(root), str(stage)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(staged.returncode, 0, staged.stderr)
            for relative_path in (
                "config/pooler.example.yaml",
                "deploy/pooler.example.yaml",
                "deploy/pooler.service",
                "docs/deployment.md",
                "scripts/check-deployment-config.py",
                "scripts/install-system-pooler.sh",
                "scripts/test-system-install.sh",
                "scripts/check-staged-secrets.sh",
                "scripts/release.sh",
            ):
                self.assertTrue((stage / relative_path).is_file(), relative_path)
            self.assertFalse((stage / "deploy/config").exists())
            self.assertFalse((stage / "Dockerfile").exists())

            (root / "config" / "unsafe.example.yaml").symlink_to(
                root / "config" / "pooler.example.yaml"
            )
            rejected = subprocess.run(
                [str(ASSET_STAGER), str(root), str(Path(temporary_directory) / "stage-unsafe")],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("symlink", rejected.stderr)

    def test_sbom_cli_output_is_deterministic(self) -> None:
        metadata = {
            "packages": [
                {
                    "name": "pooler-cli",
                    "version": "0.1.0",
                    "source": None,
                    "license": "Apache-2.0",
                    "repository": "https://github.com/coder-company/pooler",
                    "dependencies": [],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            metadata_path = temporary / "metadata.json"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            outputs: list[tuple[str, str]] = []
            for iteration in range(2):
                cdx = temporary / f"{iteration}.cdx.json"
                spdx = temporary / f"{iteration}.spdx.json"
                subprocess.run(
                    [
                        "python3",
                        str(SBOM_PATH),
                        "--metadata",
                        str(metadata_path),
                        "--version",
                        "0.1.0",
                        "--epoch",
                        "0",
                        "--assets-manifest",
                        str(MANIFEST),
                        "--cyclonedx",
                        str(cdx),
                        "--spdx",
                        str(spdx),
                    ],
                    check=True,
                )
                outputs.append(
                    (cdx.read_text(encoding="utf-8"), spdx.read_text(encoding="utf-8"))
                )
            self.assertEqual(outputs[0], outputs[1])

    def test_target_specific_sbom_documents_have_unique_identities(self) -> None:
        package = {
            "name": "pooler-cli",
            "version": "0.1.0",
            "source": None,
            "license": "Apache-2.0",
            "dependencies": [],
        }
        linux_cdx = SBOM.render_cyclonedx(
            [package], "0.1.0", 0, target="x86_64-unknown-linux-gnu"
        )
        arm_cdx = SBOM.render_cyclonedx(
            [package], "0.1.0", 0, target="aarch64-unknown-linux-gnu"
        )
        linux_spdx = SBOM.render_spdx(
            [package], "0.1.0", 0, target="x86_64-unknown-linux-gnu"
        )
        arm_spdx = SBOM.render_spdx(
            [package], "0.1.0", 0, target="aarch64-unknown-linux-gnu"
        )
        self.assertNotEqual(linux_cdx["serialNumber"], arm_cdx["serialNumber"])
        self.assertNotEqual(
            linux_spdx["documentNamespace"], arm_spdx["documentNamespace"]
        )

    def test_local_and_hosted_release_paths_copy_the_inventory(self) -> None:
        local_release = (ROOT / "scripts" / "release.sh").read_text(encoding="utf-8")
        hosted_release = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'cp -R "$root_directory/third-party/dashboard-assets" "$stage/third-party/"',
            local_release,
        )
        self.assertIn(
            'cp -R third-party/dashboard-assets "$stage/third-party/"',
            hosted_release,
        )
        self.assertIn('"$asset_stager" "$root_directory" "$stage"', local_release)
        self.assertEqual(hosted_release.count("--assets-manifest"), 2)


if __name__ == "__main__":
    unittest.main()
