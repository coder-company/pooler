# Failure-injection corpus

`corpus.json` is the small, deterministic fault matrix used by the deep test
workflow. It contains no network addresses, credentials, prompts, or provider
traffic. Each case declares its protocol boundary, commitment point, expected
attempt count, and expected health mutation.

`pooler-testkit` validates the matrix contract. The `pooler-server` integration
runner executes every case through a bound Pooler listener and real upstream
wire behavior. It asserts the declared attempts and account health after the
request, including no retry after commitment and no credential cooldown for an
invalid request. The runner also drains the server and verifies its tracked
tasks, permits, refresh leases, temporary files, and secret material return to
zero.

The corpus is a source of test cases, not a compatibility claim. Add a case
when a transport or adapter boundary gains a new failure mode; keep the case
bounded and reproducible.
