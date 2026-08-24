# Quickstart

This guide shows you how to initialize, configure, verify, and start Pooler.

## Prerequisites

- Built or installed `pooler` binary (or Rust toolchain with `cargo`).
- An API key for an AI provider (such as OpenAI, Anthropic, or Google Gemini).

## 1. Initialize a starter deployment

Create an owner-private starter configuration directory:

```sh
pooler init --output pooler-starter
```

The command creates a directory with restricted permissions (`0700` on Unix) containing:
- `pooler.yaml`: Preconfigured, compiler-validated YAML configuration.
- `management.token`: Random bearer token for the management dashboard and API.
- `store.key`: Random key for the encrypted credential store.
- `provider.key`: Empty file for storing your upstream provider API key.

## 2. Add your provider API key

Write your API key to `pooler-starter/provider.key`:

```sh
echo "sk-your-actual-api-key-here" > pooler-starter/provider.key
chmod 0600 pooler-starter/provider.key
```

Alternatively, export the key to an environment variable:

```sh
export OPENAI_API_KEY="sk-your-actual-api-key-here"
```

## 3. Validate the configuration

Run the compiler check to verify configuration syntax and route compilation:

```sh
pooler check --config pooler-starter/pooler.yaml
```

## 4. Run preflight diagnostics

Run the non-billable preflight check to probe DNS, TLS, and upstream endpoint connectivity:

```sh
pooler --config pooler-starter/pooler.yaml preflight
```

Preflight sends zero inference requests (`inference_requests_sent: 0`) and verifies that your network can reach upstream providers.

## 5. Start the Pooler runtime

Start the proxy server and management listener:

```sh
pooler --config pooler-starter/pooler.yaml \
  --credential-key-ref file:$(pwd)/pooler-starter/store.key \
  serve
```

Pooler binds:
- Main AI Proxy on `http://127.0.0.1:8319` (or the port defined in your configuration).
- Management Dashboard on `http://127.0.0.1:18477`.

## 6. Open the management dashboard

In another terminal, launch the authenticated web dashboard:

```sh
pooler --config pooler-starter/pooler.yaml dashboard
```

The command opens your default browser to `http://127.0.0.1:18477/dashboard`.

## 7. Connect your client or SDK

Point your AI client or SDK to the local Pooler endpoint:

### OpenAI Python SDK
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8319/v1",
    api_key="not-needed" # Upstream credentials are handled server-side
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello via Pooler!"}]
)
print(response.choices[0].message.content)
```

### cURL
```sh
curl http://127.0.0.1:8319/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Ping"}]
  }'
```

## Next steps

- Explore [Agent Native Prompts](agent-native.md) for automated agent setup.
- Configure [Adapters & Presets](adapters-and-presets.md) for Cursor, Devin, or Factory Droid.
- Learn about [Provider Login & OAuth](provider-login.md) to use browser or device authorization.
- Set up [Production Deployment](deployment.md) with Docker or systemd.
