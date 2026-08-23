// Render every @lobehub/icons Mono component to static SVG and emit a JSON
// registry consumed by scripts/generate-management-ui-assets.py.
//
// Usage:
//   npm pack @lobehub/icons@5.16.0 && tar xzf lobehub-icons-5.16.0.tgz
//   node scripts/extract-lobehub-icons.mjs package/es provider-icons.json --patch
//
// Run the script from the directory that contains node_modules (Node resolves
// the react import relative to the script location).
//
// The package ships compiled ESM with extensionless "../style" imports; run
// with --patch to rewrite them in place before importing (Node requires the
// explicit extension and "type": "module" in the extracted package.json).
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { join, relative, resolve } from "node:path";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

const EXPECTED_INPUTS = {
  "@lobehub/icons": "5.16.0",
  "es-toolkit": "1.51.0",
  react: "19.2.8",
  "react-dom": "19.2.8",
};
const EXPECTED_ICON_COUNT = 319;
const EXPECTED_OUTPUT_SHA256 =
  "0cf5f4673a80639ee5f37f2d741cfdad5524e0a3afd77d3a2601685137544bdd";

const [esDirArg, outArg, ...flags] = process.argv.slice(2);
if (!esDirArg || !outArg) {
  console.error("usage: node extract-lobehub-icons.mjs <package/es dir> <out.json> [--patch]");
  process.exit(2);
}
const esDir = resolve(esDirArg);
const packageManifest = JSON.parse(
  readFileSync(join(esDir, "..", "package.json"), "utf8"),
);
if (
  packageManifest.name !== "@lobehub/icons" ||
  packageManifest.version !== EXPECTED_INPUTS["@lobehub/icons"]
) {
  throw new Error("unexpected @lobehub/icons package; expected 5.16.0");
}
const require = createRequire(import.meta.url);
for (const name of ["es-toolkit", "react", "react-dom"]) {
  const manifest = JSON.parse(readFileSync(require.resolve(`${name}/package.json`), "utf8"));
  if (manifest.version !== EXPECTED_INPUTS[name]) {
    throw new Error(`unexpected ${name} package; expected ${EXPECTED_INPUTS[name]}`);
  }
}

if (flags.includes("--patch")) {
  const packageJson = join(esDir, "..", "package.json");
  const manifest = JSON.parse(readFileSync(packageJson, "utf8"));
  manifest.type = "module";
  writeFileSync(packageJson, JSON.stringify(manifest, null, 2));
  let patched = 0;
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry);
      if (statSync(path).isDirectory()) walk(path);
      else if (entry.endsWith(".js")) {
        const text = readFileSync(path, "utf8");
        let next = text.replace(
          /(from\s+["'])(\.\.\/)+style(["'])/g,
          (_m, head, dots, tail) => head + dots + "style.js" + tail,
        );
        // Extensionless/misplaced hook imports: resolve against the icon
        // directory root first, then the shared es/hooks directory.
        next = next.replace(
          /from\s+["']((?:\.\.\/)+|\.\/)hooks\/([A-Za-z]+)(?:\.js)?["']/g,
          (match, dots, name) => {
            const candidates = [
              join(dir, "..", `${name}.js`),
              join(dir, "..", "hooks", `${name}.js`),
              join(esDir, "hooks", `${name}.js`),
            ];
            const found = candidates.find((candidate) => {
              try {
                statSync(candidate);
                return true;
              } catch {
                return false;
              }
            });
            if (!found) return match;
            const rel = relative(dir, found).replaceAll("\\", "/");
            return `from "${rel.startsWith(".") ? rel : "./" + rel}"`;
          },
        );
        if (next !== text) {
          writeFileSync(path, next);
          patched += 1;
        }
      }
    }
  };
  walk(esDir);
  console.error(`patched ${patched} files`);
}

const skip = new Set(["components", "features", "hooks"]);
const out = {};

for (const entry of readdirSync(esDir)) {
  const dir = join(esDir, entry);
  if (skip.has(entry) || !statSync(dir).isDirectory()) continue;
  const monoPath = join(dir, "components", "Mono.js");
  try {
    statSync(monoPath);
  } catch {
    continue;
  }
  try {
    const mod = await import(monoPath);
    const markup = renderToStaticMarkup(React.createElement(mod.default, { size: 24 }));
    const viewBox = markup.match(/viewBox="([^"]+)"/)?.[1] ?? "0 0 24 24";
    const inner = markup
      .replace(/^<svg[^>]*>/, "")
      .replace(/<\/svg>$/, "")
      .replace(/<title>.*?<\/title>/s, "")
      .trim();
    if (!inner) continue;
    out[entry.toLowerCase()] = { viewBox, body: inner };
  } catch (error) {
    console.error(`skip ${entry}: ${error.message}`);
  }
}

const output = JSON.stringify(out);
const checksum = createHash("sha256").update(output).digest("hex");
if (Object.keys(out).length !== EXPECTED_ICON_COUNT || checksum !== EXPECTED_OUTPUT_SHA256) {
  throw new Error(`unexpected provider icon inventory: ${Object.keys(out).length} icons, sha256 ${checksum}`);
}
writeFileSync(outArg, output);
console.log(`icons: ${Object.keys(out).length}, json bytes: ${statSync(outArg).size}`);
