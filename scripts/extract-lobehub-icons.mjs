// Render every @lobehub/icons Mono component to static SVG and emit a JSON
// registry consumed by scripts/generate-management-ui-assets.py.
//
// Usage:
//   npm pack @lobehub/icons && tar xzf lobehub-icons-*.tgz
//   npm install react react-dom
//   node scripts/extract-lobehub-icons.mjs package/es provider-icons.json
//
// The package ships compiled ESM with extensionless "../style" imports; run
// with --patch to rewrite them in place before importing (Node requires the
// explicit extension and "type": "module" in the extracted package.json).
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

const [esDirArg, outArg, ...flags] = process.argv.slice(2);
if (!esDirArg || !outArg) {
  console.error("usage: node extract-lobehub-icons.mjs <package/es dir> <out.json> [--patch]");
  process.exit(2);
}
const esDir = resolve(esDirArg);

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
        const next = text.replace(
          /(from\s+["'])(\.\.\/)+style(["'])/g,
          (_m, head, dots, tail) => head + dots + "style.js" + tail,
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

writeFileSync(outArg, JSON.stringify(out));
console.log(`icons: ${Object.keys(out).length}, json bytes: ${statSync(outArg).size}`);
