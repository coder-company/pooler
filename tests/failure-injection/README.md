# Failure-injection corpus

`corpus.json` is the small, deterministic fault matrix used by the deep test
workflow. It contains no network addresses, credentials, prompts, or provider
traffic. The `kind` and `commitment` fields are intentionally explicit so a
fixture runner can verify both error classification and the no-retry-after-
commitment invariant.

The corpus is a source of test cases, not a compatibility claim. Add a case
when a transport or adapter boundary gains a new failure mode; keep the case
bounded and reproducible.
