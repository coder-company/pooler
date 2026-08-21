# Embedded dashboard asset provenance

`manifest.json` inventories the non-Cargo icon, font, and brand-mark material
embedded in Pooler's management dashboard. Paths in `embedded_assets` are
repository-relative. Known upstream license texts are preserved under
`licenses/` and are shipped with release archives.

The manifest distinguishes an asset's own version from a packaging version
(for example, Geist 1.401 distributed by `@fontsource-variable/geist` 5.2.8).
A JSON `null` or SPDX `NOASSERTION` means the source material available when
this inventory was prepared did not establish that fact. In particular, the
Coder Company mark source had no recorded version, immutable source revision,
copyright owner, or standalone redistribution license; this inventory does
not infer any of those facts.

The license declarations describe copyright licensing only. Provider names,
logos, and the Coder Company marks may also be subject to trademark or other
rights that are not granted by those licenses.
