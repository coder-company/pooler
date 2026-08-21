//! Static, authenticated management control surface.
//!
//! The UI intentionally has no build step or third-party runtime. It is
//! served by the authenticated management listener and reads the redacted
//! JSON endpoints exposed by [`super::ManagementApi`]. Keeping the assets in
//! the server binary makes the control surface available in release bundles
//! without a separate web deployment.
//!
//! Source files live in `crates/pooler-server/ui/` and are embedded at
//! compile time. Generated assets (icons, brand marks, fonts) are produced by
//! `scripts/generate-management-ui-assets.py` and committed.

/// Return one embedded UI asset by its management-relative path.
pub(crate) fn asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    let path = if path == "/ui/" { "/ui" } else { path };
    TEXT_ASSETS
        .iter()
        .find_map(|(name, content_type, body)| {
            (*name == path).then_some((*content_type, body.as_bytes()))
        })
        .or_else(|| {
            BINARY_ASSETS
                .iter()
                .find_map(|(name, content_type, body)| (*name == path).then_some((*content_type, *body)))
        })
}

const TEXT_ASSETS: &[(&str, &str, &str)] = &[
    (
        "/ui",
        "text/html; charset=utf-8",
        include_str!("../ui/index.html"),
    ),
    (
        "/ui.css",
        "text/css; charset=utf-8",
        include_str!("../ui/app.css"),
    ),
    (
        "/ui.js",
        "application/javascript; charset=utf-8",
        include_str!("../ui/app.js"),
    ),
    (
        "/ui/icons.js",
        "application/javascript; charset=utf-8",
        include_str!("../ui/icons.js"),
    ),
    (
        "/ui/providers.js",
        "application/javascript; charset=utf-8",
        include_str!("../ui/providers.js"),
    ),
];

const PNG: &str = "image/png";
const WOFF2: &str = "font/woff2";

const BINARY_ASSETS: &[(&str, &str, &[u8])] = &[
    // Brand marks (Coder Company mark, recoloured onto transparency).
    ("/ui/assets/mark-charcoal-32.png", PNG, include_bytes!("../ui/assets/mark-charcoal-32.png")),
    ("/ui/assets/mark-charcoal-64.png", PNG, include_bytes!("../ui/assets/mark-charcoal-64.png")),
    ("/ui/assets/mark-charcoal-128.png", PNG, include_bytes!("../ui/assets/mark-charcoal-128.png")),
    ("/ui/assets/mark-charcoal-256.png", PNG, include_bytes!("../ui/assets/mark-charcoal-256.png")),
    ("/ui/assets/mark-warm-black-32.png", PNG, include_bytes!("../ui/assets/mark-warm-black-32.png")),
    ("/ui/assets/mark-warm-black-64.png", PNG, include_bytes!("../ui/assets/mark-warm-black-64.png")),
    ("/ui/assets/mark-warm-black-128.png", PNG, include_bytes!("../ui/assets/mark-warm-black-128.png")),
    ("/ui/assets/mark-warm-black-256.png", PNG, include_bytes!("../ui/assets/mark-warm-black-256.png")),
    ("/ui/assets/mark-paper-32.png", PNG, include_bytes!("../ui/assets/mark-paper-32.png")),
    ("/ui/assets/mark-paper-64.png", PNG, include_bytes!("../ui/assets/mark-paper-64.png")),
    ("/ui/assets/mark-paper-128.png", PNG, include_bytes!("../ui/assets/mark-paper-128.png")),
    ("/ui/assets/mark-paper-256.png", PNG, include_bytes!("../ui/assets/mark-paper-256.png")),
    ("/ui/assets/mark-white-32.png", PNG, include_bytes!("../ui/assets/mark-white-32.png")),
    ("/ui/assets/mark-white-64.png", PNG, include_bytes!("../ui/assets/mark-white-64.png")),
    ("/ui/assets/mark-white-128.png", PNG, include_bytes!("../ui/assets/mark-white-128.png")),
    ("/ui/assets/mark-white-256.png", PNG, include_bytes!("../ui/assets/mark-white-256.png")),
    ("/ui/assets/mark-stone-32.png", PNG, include_bytes!("../ui/assets/mark-stone-32.png")),
    ("/ui/assets/mark-stone-64.png", PNG, include_bytes!("../ui/assets/mark-stone-64.png")),
    ("/ui/assets/mark-stone-128.png", PNG, include_bytes!("../ui/assets/mark-stone-128.png")),
    ("/ui/assets/mark-stone-256.png", PNG, include_bytes!("../ui/assets/mark-stone-256.png")),
    // Favicons.
    ("/ui/assets/favicon-warm-black-32.png", PNG, include_bytes!("../ui/assets/favicon-warm-black-32.png")),
    ("/ui/assets/favicon-warm-black-64.png", PNG, include_bytes!("../ui/assets/favicon-warm-black-64.png")),
    ("/ui/assets/favicon-paper-32.png", PNG, include_bytes!("../ui/assets/favicon-paper-32.png")),
    ("/ui/assets/favicon-paper-64.png", PNG, include_bytes!("../ui/assets/favicon-paper-64.png")),
    // Fonts (Geist variable and Geist Mono, SIL OFL 1.1).
    ("/ui/fonts/geist-latin.woff2", WOFF2, include_bytes!("../ui/fonts/geist-latin.woff2")),
    ("/ui/fonts/geist-latin-ext.woff2", WOFF2, include_bytes!("../ui/fonts/geist-latin-ext.woff2")),
    ("/ui/fonts/geist-cyrillic.woff2", WOFF2, include_bytes!("../ui/fonts/geist-cyrillic.woff2")),
    ("/ui/fonts/geist-mono.woff2", WOFF2, include_bytes!("../ui/fonts/geist-mono.woff2")),
];
