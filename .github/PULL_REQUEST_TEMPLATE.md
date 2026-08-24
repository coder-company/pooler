<!--
Do not use a pull request to report a security vulnerability. Report privately
at https://github.com/coder-company/pooler/security/advisories/new
-->

## What changed

<!-- The user-visible effect, in a sentence or two. Describe behavior, not the diff. -->

## Why

<!-- The problem this solves. Link the issue it closes, if there is one. -->

## How it was verified

<!--
List the commands you actually ran and their result. Say so plainly if you could
not verify something.
-->

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-features --locked`
- [ ] `python3 scripts/check-docs-links.py`
- [ ] `python3 scripts/check-docs-examples.py --require-binary`

Additional verification, if this change needs it:

- [ ] `./scripts/check-config-schema.sh` after regenerating with `./scripts/generate-config-schema.sh` (configuration types changed)
- [ ] `./scripts/verify-compatibility-fixtures.py` (adapter or codec behavior changed)
- [ ] `scripts/deep-test.sh --no-fuzz` (failure handling or security boundaries changed)
- [ ] `cargo deny check` (dependencies changed)

## Checks

- [ ] No literal secret, token, API key, or real prompt appears in the diff, tests, or fixtures.
- [ ] Documentation matches what the binary now does, including any command, path, port, or preset parameter I touched.
- [ ] Unsupported behavior is rejected rather than approximated, and any conversion loss is reported through the route's `loss_policy`.
- [ ] New bounds are explicit, and existing bounds are not widened without a stated reason.
- [ ] Management responses, logs, traces, audit events, and exports stay metadata-only.

## Anything reviewers should look at closely

<!-- Trade-offs you made, alternatives you rejected, or areas you are unsure about. -->
