#!/usr/bin/env python3
"""Focused checks for dashboard asset release provenance and SBOM rendering."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "third-party" / "dashboard-assets" / "manifest.json"
SBOM_PATH = ROOT / "scripts" / "sbom.py"
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
        self.assertEqual(hosted_release.count("--assets-manifest"), 2)


if __name__ == "__main__":
    unittest.main()
