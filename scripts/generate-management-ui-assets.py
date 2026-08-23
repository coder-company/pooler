#!/usr/bin/env python3
"""Generate the embedded management-UI assets for the Pooler dashboard.

The management UI is embedded in the `pooler-server` binary without a build
step (see `crates/pooler-server/src/management_ui.rs`).  This script is the
deterministic, re-runnable pipeline that produces the generated assets under
`crates/pooler-server/ui/`:

* `icons.js` — Iconoir SVG bodies (the icon family used by arcXiv) extracted
  from a local `@iconify-icons/iconoir` installation into a tiny registry.
* `providers.js` — monochrome provider brand logos (currentColor SVG bodies)
  from `@lobehub/icons` (MIT), plus a handful of Simple Icons (CC0) gap fills,
  with a fuzzy resolver that maps pooler provider/model IDs to a brand slug.
  The input JSON is produced by `scripts/extract-lobehub-icons.mjs`.
* `assets/mark-*.png` — the Coder Company mark recoloured onto transparency
  for every dashboard colourway, trimmed and resized for web use.
* `fonts/*.woff2` — Geist variable (sans) copied from `@fontsource-variable/geist`
  and Geist Mono converted from TTF with fonttools.

The generated files are committed; the script only needs to run when the
brand kit or the icon set changes.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent
UI_DIR = REPO_ROOT / "crates" / "pooler-server" / "ui"

# Simple Icons (CC0) slugs merged in when @lobehub/icons has no equivalent.
SIMPLE_ICONS_GAP_FILLS = [
    "deepgram",
    "github",
    "gitlab",
    "docker",
    "digitalocean",
    "amd",
    "clarifai",
    "modal",
    "scaleway",
    "hetzner",
    "vultr",
    "warp",
    "ovh",
]

# Provider logos larger than this are detailed illustrations, not glyphs;
# they are dropped and fall back to the monogram tile.
PROVIDER_BODY_MAX_BYTES = 30_000

# Keyword → lobehub slug, for names that differ from the registry slug.
# Matched as substrings of the normalized provider/model ID; the generator
# sorts longest-keyword-first and drops aliases whose slug is not registered.
PROVIDER_ALIASES = {
    # OpenAI family (o-series handled by a regex in the resolver)
    "gpt": "openai",
    "chatgpt": "openai",
    "whisper": "openai",
    # Google
    "vertex": "vertexai",
    "bard": "gemini",
    "veo": "google",
    "gcp": "googlecloud",
    # Meta
    "llama": "meta",
    # Mistral
    "mixtral": "mistral",
    "codestral": "mistral",
    "devstral": "mistral",
    "magistral": "mistral",
    "pixtral": "mistral",
    "voxtral": "mistral",
    # Cohere
    "command": "commanda",
    # Alibaba
    "tongyi": "qwen",
    # Zhipu
    "glm": "chatglm",
    # Baidu
    "ernie": "baidu",
    "qianfan": "baiducloud",
    # ByteDance
    "seedream": "bytedance",
    # Xiaomi
    "mimo": "xiaomimimo",
    "xiaomi": "xiaomimimo",
    # Kilo Code
    "kilo": "kilocode",
    # OVHcloud
    "ovhcloud": "ovh",
    # 01.AI
    "lingyi": "yi",
    "01ai": "zeroone",
    # StepFun
    "step": "stepfun",
    # SiliconFlow
    "siliconflow": "siliconcloud",
    # AWS
    "amazon": "aws",
    "sagemaker": "aws",
    # Microsoft
    "foundry": "azureai",
    # DigitalOcean
    "gradient": "digitalocean",
    # Lepton
    "lepton": "leptonai",
    # AI21
    "jamba": "ai21",
    # Aleph Alpha
    "luminous": "alephalpha",
    # Nous Research
    "nous": "nousresearch",
    "hermes": "nousresearch",
    # Upstage
    "solar": "upstage",
    # Perplexity
    "sonar": "perplexity",
    # Windsurf
    "codeium": "windsurf",
    # Black Forest Labs
    "blackforest": "bfl",
    # Luma
    "dreammachine": "luma",
    # Snowflake
    "arctic": "snowflake",
    # Databricks
    "databricks": "dbrx",
}

# Three-character slugs that are safe to substring-match as themselves.
SAFE_SHORT_SELF_ALIASES = [
    "aws",
    "xai",
    "fal",
    "ibm",
    "mcp",
    "n8n",
    "bfl",
    "tii",
    "zai",
    "ai2",
    "aya",
]

# Iconoir icons used by the dashboard, mirroring arcXiv's iconography.
ICONS = [
    # Primary navigation
    "dashboard",
    "cpu",
    "key-alt",
    "graph-up",
    "tools",
    "activity",
    "settings",
    # Status
    "check-circle",
    "warning-circle",
    "warning-triangle",
    "info-empty",
    "cancel",
    "circle",
    # Actions and chrome
    "refresh",
    "refresh-double",
    "cloud-download",
    "search",
    "filter",
    "copy",
    "nav-arrow-down",
    "arrow-right",
    "open-new-window",
    "more-vert",
    "switch-on",
    "switch-off",
    "play",
    "pause",
    "trash",
    "lock",
    "clock-rotate-right",
    "list",
    "page",
    "database-rounded",
    "globe",
    "server",
    "wallet",
    "hourglass",
    "timer",
    "shield",
    "package",
    "sun-light",
    "half-moon",
    "check",
    "log-out",
    "eye-empty",
    "eye-off",
]

# Brand colourways derived from the Coder Company design tokens.
MARK_COLOURS = {
    "charcoal": (59, 58, 53),  # #3B3A35 — light surfaces
    "warm-black": (23, 23, 19),  # #171713 — favicon on paper
    "paper": (243, 240, 232),  # #F3F0E8 — dark surfaces
    "white": (255, 255, 255),  # #FFFFFF — small sizes on warm black
    "stone": (184, 180, 167),  # #B8B4A7 — quiet dark placements
}

MARK_SIZES = (32, 64, 128, 256)

def extract_icons(iconoir_dir: Path) -> dict[str, dict[str, object]]:
    icons: dict[str, dict[str, object]] = {}
    pattern = re.compile(
        r'"width":\s*(?P<width>\d+),\s*"height":\s*(?P<height>\d+),\s*'
        r'"body":\s*(?P<body>"(?:[^"\\]|\\.)*")',
        re.DOTALL,
    )
    missing = []
    for name in ICONS:
        source = iconoir_dir / f"{name}.js"
        if not source.exists():
            missing.append(name)
            continue
        match = pattern.search(source.read_text(encoding="utf-8"))
        if not match:
            missing.append(name)
            continue
        icons[name] = {
            "width": int(match.group("width")),
            "height": int(match.group("height")),
            "body": json.loads(match.group("body")),
        }
    if missing:
        raise SystemExit(f"missing Iconoir icons in {iconoir_dir}: {', '.join(missing)}")
    return icons


def write_icons_js(icons: dict[str, dict[str, object]]) -> Path:
    entries = []
    for name in ICONS:
        entry = icons[name]
        body = json.dumps(entry["body"], ensure_ascii=False)
        entries.append(
            f'  {json.dumps(name)}: {{"width": {entry["width"]}, '
            f'"height": {entry["height"]}, "body": {body}}}'
        )
    payload = "{\n" + ",\n".join(entries) + "\n}"
    # Build the module without f-string brace escaping pitfalls.
    lines = [
        "// Generated by scripts/generate-management-ui-assets.py. Do not edit by hand.",
        "// Iconoir (MIT) SVG bodies, matching the arcXiv iconography.",
        '"use strict";',
        "",
        "const _ICONS = " + payload + ";",
        "",
        "function iconSvg(name, size = 20) {",
        "  const entry = _ICONS[name];",
        '  if (!entry) return "";',
        '  return `<svg viewBox="0 0 ${entry.width} ${entry.height}" width="${size}" height="${size}" fill="none" aria-hidden="true">${entry.body}</svg>`;',
        "}",
        "",
    ]
    target = UI_DIR / "icons.js"
    target.write_text("\n".join(lines), encoding="utf-8")
    return target


def _minify_svg_body(slug: str, body: str) -> str:
    body = re.sub(r">\s+<", "><", body.strip())
    body = body.replace(' style="mask-type:alpha"', ' mask-type="alpha"')
    if re.search(r"\sstyle=", body, re.IGNORECASE):
        raise SystemExit(f"provider icon {slug} contains an unsupported inline style")
    ids = re.findall(r'id="([^"]+)"', body)
    for ident in ids:
        namespaced = f"pl-{slug}-{ident}"
        body = body.replace(f'"{ident}"', f'"{namespaced}"')
        body = body.replace(f"#{ident})", f"#{namespaced})")
        body = body.replace(f'#{ident}"', f'#{namespaced}"')
        body = body.replace(f"#{ident}'", f"#{namespaced}'")
    return body


def load_provider_icons(
    provider_icons_json: Path, simple_icons_dir: Path
) -> dict[str, dict[str, str]]:
    raw = json.loads(provider_icons_json.read_text(encoding="utf-8"))
    registry: dict[str, dict[str, str]] = {}
    dropped = []
    for slug, entry in sorted(raw.items()):
        body = _minify_svg_body(slug, entry["body"])
        if len(body.encode("utf-8")) > PROVIDER_BODY_MAX_BYTES:
            dropped.append(slug)
            continue
        registry[slug] = {"viewBox": entry["viewBox"], "body": body}
    for slug in SIMPLE_ICONS_GAP_FILLS:
        if slug in registry:
            continue
        source = simple_icons_dir / f"{slug}.svg"
        if not source.exists():
            dropped.append(slug)
            continue
        text = source.read_text(encoding="utf-8")
        viewbox = re.search(r'viewBox="([^"]+)"', text)
        match = re.search(r"<svg[^>]*>(.*?)</svg>", text, re.DOTALL)
        if not match:
            dropped.append(slug)
            continue
        body = re.sub(r"<title>.*?</title>", "", match.group(1), flags=re.DOTALL)
        registry[slug] = {
            "viewBox": viewbox.group(1) if viewbox else "0 0 24 24",
            "body": _minify_svg_body(slug, body),
        }
    if dropped:
        print(f"provider icons dropped (oversized or missing): {', '.join(dropped)}")
    return registry


def provider_alias_pairs(registry: dict[str, dict[str, str]]) -> list[list[str]]:
    pairs: dict[str, str] = {}
    for keyword, slug in PROVIDER_ALIASES.items():
        if len(keyword) < 3 or keyword in registry:
            continue
        if slug not in registry:
            print(f"provider alias dropped (no such slug): {keyword} -> {slug}")
            continue
        pairs[keyword] = slug
    for slug in SAFE_SHORT_SELF_ALIASES:
        if slug in registry:
            pairs.setdefault(slug, slug)
    return [[keyword, pairs[keyword]] for keyword in sorted(pairs, key=lambda k: (-len(k), k))]


def write_providers_js(registry: dict[str, dict[str, str]]) -> Path:
    entries = []
    for slug in sorted(registry):
        entry = registry[slug]
        entries.append(
            f"  {json.dumps(slug)}: {{"
            f'"viewBox": {json.dumps(entry["viewBox"])}, '
            f'"body": {json.dumps(entry["body"], ensure_ascii=False)}}}'
        )
    payload = "{\n" + ",\n".join(entries) + "\n}"
    aliases = json.dumps(provider_alias_pairs(registry), ensure_ascii=False)
    lines = [
        "// Generated by scripts/generate-management-ui-assets.py. Do not edit by hand.",
        "// Provider brand glyphs: @lobehub/icons (MIT) Mono variants plus Simple",
        "// Icons (CC0) gap fills. All render in currentColor to match the theme.",
        '"use strict";',
        "",
        "const _PROVIDERS = " + payload + ";",
        "let _providerLogoInstance = 0;",
        "",
        "const _PROVIDER_ALIASES = " + aliases + ";",
        "",
        "const _PROVIDER_SLUGS_BY_LENGTH = Object.keys(_PROVIDERS)",
        "  .filter((slug) => slug.length >= 4)",
        "  .sort((a, b) => b.length - a.length);",
        "",
        "function resolveProviderSlug(name) {",
        '  const norm = String(name || "").toLowerCase().replace(/[^a-z0-9]/g, "");',
        "  if (!norm) return null;",
        "  if (_PROVIDERS[norm]) return norm;",
        '  if (/^o\\d/.test(norm) && _PROVIDERS.openai) return "openai";',
        "  for (const pair of _PROVIDER_ALIASES) {",
        "    if (norm.indexOf(pair[0]) !== -1 && _PROVIDERS[pair[1]]) return pair[1];",
        "  }",
        "  for (const slug of _PROVIDER_SLUGS_BY_LENGTH) {",
        "    if (norm.indexOf(slug) !== -1) return slug;",
        "  }",
        "  return null;",
        "}",
        "",
        "function providerLogoSvg(name, size = 18) {",
        "  const slug = resolveProviderSlug(name);",
        "  if (!slug) return null;",
        "  const entry = _PROVIDERS[slug];",
        '  const prefix = `pl-instance-${++_providerLogoInstance}-`;',
        '  const body = entry.body.replace(/\\bid="([^"]+)"/g, (_match, id) => `id="${prefix}${id}"`).replace(/url\\(#([^)]+)\\)/g, (_match, id) => `url(#${prefix}${id})`).replace(/(href|xlink:href)="#([^"]+)"/g, (_match, attr, id) => `${attr}="#${prefix}${id}"`);',
        '  return `<svg class="provider-logo" data-provider-logo="${slug}" viewBox="${entry.viewBox}" width="${size}" height="${size}" fill="currentColor" aria-hidden="true">${body}</svg>`;',
        "}",
        "",
        "function providerBadge(name, size = 18) {",
        "  const logo = providerLogoSvg(name, size);",
        "  if (logo) return logo;",
        "  const letter = (String(name || '').match(/[a-z0-9]/i) || ['?'])[0].toUpperCase();",
        "  const safeSize = [13, 16, 18].includes(Number(size)) ? Number(size) : 18;",
        '  return `<span class="provider-monogram provider-monogram-${safeSize}" aria-hidden="true">${letter}</span>`;',
        "}",
        "",
    ]
    target = UI_DIR / "providers.js"
    target.write_text("\n".join(lines), encoding="utf-8")
    return target


def recolour_mark(master: Image.Image, colour: tuple[int, int, int]) -> Image.Image:
    alpha = master.split()[-1]
    recoloured = Image.new("RGBA", master.size, (*colour, 255))
    recoloured.putalpha(alpha)
    return recoloured


def trimmed_master(brand_kit: Path) -> Image.Image:
    source = (
        brand_kit
        / "01-logo"
        / "mark"
        / "coder-company-mark-charcoal-transparent-master.png"
    )
    master = Image.open(source).convert("RGBA")
    bbox = master.split()[-1].getbbox()
    if bbox is None:
        raise SystemExit(f"{source} has no opaque pixels")
    trimmed = master.crop(bbox)
    # Restore a small uniform clear space so the mark never touches the edge.
    pad = round(max(trimmed.size) * 0.04)
    canvas = Image.new(
        "RGBA", (trimmed.width + 2 * pad, trimmed.height + 2 * pad), (0, 0, 0, 0)
    )
    canvas.paste(trimmed, (pad, pad))
    return canvas


def write_marks(brand_kit: Path) -> list[Path]:
    master = trimmed_master(brand_kit)
    written = []
    for colour_name, colour in MARK_COLOURS.items():
        recoloured = recolour_mark(master, colour)
        for size in MARK_SIZES:
            resized = recoloured.resize(
                (size, round(size * recoloured.height / recoloured.width)),
                Image.LANCZOS,
            )
            target = UI_DIR / "assets" / f"mark-{colour_name}-{size}.png"
            resized.save(target, optimize=True)
            written.append(target)
    # Favicons: warm-black mark for light browser chrome, paper for dark.
    for size in (32, 64):
        for colour_name in ("warm-black", "paper"):
            recoloured = recolour_mark(master, MARK_COLOURS[colour_name])
            resized = recoloured.resize(
                (size, round(size * recoloured.height / recoloured.width)),
                Image.LANCZOS,
            )
            target = UI_DIR / "assets" / f"favicon-{colour_name}-{size}.png"
            resized.save(target, optimize=True)
            written.append(target)
    return written


def write_fonts(geist_dir: Path, geist_mono_ttf: Path) -> list[Path]:
    written = []
    fonts_dir = UI_DIR / "fonts"
    for subset in ("latin", "latin-ext", "cyrillic"):
        source = geist_dir / f"geist-{subset}-wght-normal.woff2"
        if not source.exists():
            raise SystemExit(f"missing Geist subset: {source}")
        target = fonts_dir / f"geist-{subset}.woff2"
        shutil.copyfile(source, target)
        written.append(target)
    target = fonts_dir / "geist-mono.woff2"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "fontTools.subset",
            str(geist_mono_ttf),
            f"--output-file={target}",
            "--flavor=woff2",
            "--unicodes=U+0000-00FF,U+2000-206F,U+20AC,U+2190-21FF,U+2260,U+2264,U+2265",
            "--layout-features=*",
            "--no-hinting",
            "--desubroutinize",
        ],
        check=True,
    )
    written.append(target)
    return written


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--brand-kit", type=Path, required=True)
    parser.add_argument("--iconoir", type=Path, required=True)
    parser.add_argument("--geist", type=Path, required=True)
    parser.add_argument("--geist-mono", type=Path, required=True)
    parser.add_argument("--provider-icons", type=Path, required=True)
    parser.add_argument("--simple-icons", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    (UI_DIR / "assets").mkdir(parents=True, exist_ok=True)
    (UI_DIR / "fonts").mkdir(parents=True, exist_ok=True)

    icons = extract_icons(args.iconoir)
    icons_path = write_icons_js(icons)
    providers = load_provider_icons(args.provider_icons, args.simple_icons)
    providers_path = write_providers_js(providers)
    marks = write_marks(args.brand_kit)
    fonts = write_fonts(args.geist, args.geist_mono)

    print(f"wrote {icons_path.relative_to(REPO_ROOT)} ({len(icons)} icons)")
    print(
        f"wrote {providers_path.relative_to(REPO_ROOT)} "
        f"({len(providers)} provider logos, {providers_path.stat().st_size} bytes)"
    )
    for path in marks + fonts:
        print(f"wrote {path.relative_to(REPO_ROOT)} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
