# pooler

Pooler is a composable protocol runtime for AI clients and providers. It currently
supports strict configuration, opaque HTTP proxying, bounded JSON patch routes,
model-based routing, and composable imports and overlays. Unsupported protocol
compatibility is not advertised.

Validate the example configuration with:

```sh
cargo run -p pooler-cli -- check --config config/pooler.example.yaml
```

Render a fully expanded configuration, including imports and presets, with:

```sh
cargo run -p pooler-cli -- --config config/cursor.example.yaml config render
```

Run the opaque proxy with:

```sh
POOLER_UPSTREAM_KEY=... cargo run -p pooler-cli -- serve --config config/pooler.example.yaml
```

See the [delivery index](pooler-readgold.md), [product goal](GOAL.md), and
[architecture plan](ARCHITECTURE_PLAN.md).
