# Production deployment

Pooler is a single `pooler serve` process. Keep the hand-authored YAML and
secret references owner-private, persist the encrypted SQLite state directory,
and run the process as the dedicated UID `10001` (container) or `pooler`
(systemd). Secrets are always supplied through `file:`, `env:`, or `keyring:`
references; no image, unit, or example configuration contains a credential.

## Container (Docker Compose)

The checked-in [`docker-compose.example.yml`](../docker-compose.example.yml)
uses the production-shaped [`deploy/pooler.example.yaml`](../deploy/pooler.example.yaml).
That config binds inference to `0.0.0.0:8400` for container networking and
keeps management on `127.0.0.1:18477`. Management is not published as a host
port. The Compose health check therefore reads only the loopback `/health`
endpoint inside the container and does not require a bearer token. A custom
`POOLER_CONFIG_FILE` must retain an equivalent loopback management bind or
replace the health check deliberately.

Prepare private state and runtime-only secret files (the directories are
ignored by Docker and must not be committed):

```sh
install -d -m 0700 deploy/config deploy/data deploy/secrets
# Run the ownership-changing commands as root (or use a host UID mapped to
# 10001 when running rootless Docker).
sudo chown 10001:10001 deploy/config deploy/data deploy/secrets
sudo install -o 10001 -g 10001 -m 0600 deploy/pooler.example.yaml deploy/config/pooler.yaml
openssl rand -base64 32 | sudo install -o 10001 -g 10001 -m 0400 /dev/stdin deploy/secrets/store.key
# Write the provider key using your secret manager or copy a protected file:
sudo install -o 10001 -g 10001 -m 0400 /path/to/provider-key deploy/secrets/upstream.key
openssl rand -base64 32 | sudo install -o 10001 -g 10001 -m 0400 /dev/stdin deploy/secrets/downstream.key
```

The host files mounted into the container must be readable by UID/GID
`10001:10001`; `0400` is sufficient. Set `POOLER_CONFIG_FILE`,
`POOLER_DATA_DIR`, or `POOLER_SECRETS_DIR` when those paths live elsewhere.
Clients must send `Authorization: Bearer <downstream.key>` to the inference
port; this is a separate credential from `upstream.key` and `store.key`.
The default host bind is loopback. Publish it behind an authenticated TLS
edge only after choosing an explicit `POOLER_HOST_BIND` value.

Validate and start it from the repository root:

```sh
docker build --check .
docker compose -f docker-compose.example.yml config --quiet
cargo run --locked -p pooler-cli -- check --config deploy/pooler.example.yaml
python3 scripts/check-deployment-config.py
docker compose -f docker-compose.example.yml build --pull
docker compose -f docker-compose.example.yml up -d
docker compose -f docker-compose.example.yml ps
```

For a no-network configuration smoke test after the image is built:

```sh
docker compose -f docker-compose.example.yml run --rm --no-deps pooler \
  --config /etc/pooler/pooler.yaml check
```

The command line intentionally supplies both
`--credential-store /var/lib/pooler/credentials.sqlite3` and
`--credential-key-ref file:/run/secrets/store.key`. This keeps encrypted
credential, usage, and request metadata in the writable mounted state volume;
the image filesystem and config mount stay read-only.

## systemd

The bundled units are hardened for the gateway example below and deliberately
require its config plus upstream, downstream, and store key files. For a
different route plan or `env:`/`keyring:` secrets, copy the unit and replace
its `ConditionPathExists` and `ExecStart` inputs explicitly.

Install the release binary at `/usr/local/bin/pooler`, create the service user,
and keep one deployment under `/etc/pooler`:

```sh
if ! getent group pooler >/dev/null; then
  sudo groupadd --system --gid 10001 pooler
fi
if ! id pooler >/dev/null 2>&1; then
  sudo useradd --system --uid 10001 --gid pooler --home-dir /var/lib/pooler \
    --create-home --shell /usr/sbin/nologin pooler
fi
sudo install -d -o pooler -g pooler -m 0750 /etc/pooler /var/lib/pooler
sudo install -o pooler -g pooler -m 0640 deploy/pooler.example.yaml /etc/pooler/pooler.example.yaml
sudo install -o pooler -g pooler -m 0640 deploy/pooler.systemd.example.yaml /etc/pooler/pooler.yaml
sudo install -o pooler -g pooler -m 0400 /path/to/store.key /etc/pooler/store.key
sudo install -o pooler -g pooler -m 0400 /path/to/provider-key /etc/pooler/upstream.key
sudo install -o pooler -g pooler -m 0400 /path/to/downstream-key /etc/pooler/downstream.key
sudo install -o root -g root -m 0644 deploy/pooler.service /etc/systemd/system/pooler.service
systemctl daemon-reload
systemctl enable --now pooler.service
systemctl status pooler.service
```

Use [`pooler@.service`](../deploy/pooler@.service) for isolated instances. For
example, create the `pooler` user as above and install all five private inputs
(`pooler.yaml`, its imported `pooler.example.yaml`, `store.key`,
`upstream.key`, and `downstream.key`) in `/etc/pooler/production/`:

```sh
sudo install -d -o pooler -g pooler -m 0750 /etc/pooler/production
sudo install -o pooler -g pooler -m 0640 deploy/pooler.example.yaml \
  /etc/pooler/production/pooler.example.yaml
sudo install -o pooler -g pooler -m 0640 deploy/pooler.systemd.example.yaml \
  /etc/pooler/production/pooler.yaml
sudo install -o pooler -g pooler -m 0400 /path/to/store.key \
  /etc/pooler/production/store.key
sudo install -o pooler -g pooler -m 0400 /path/to/provider-key \
  /etc/pooler/production/upstream.key
sudo install -o pooler -g pooler -m 0400 /path/to/downstream-key \
  /etc/pooler/production/downstream.key
sudo systemctl enable --now pooler@production.service
```

Each instance writes only `/var/lib/pooler/<instance>/credentials.sqlite3`.

The systemd example binds inference to `127.0.0.1:8400`; it never exposes
plaintext inference on `0.0.0.0`. Use a local reverse proxy with TLS and client
authentication if the service must be reachable remotely.

The units perform `pooler check` before starting, send `SIGTERM` for Pooler’s
30-second graceful drain, and apply filesystem, capability, namespace, and
address-family restrictions. `ProtectSystem=strict` leaves only the encrypted
state directory writable. If a deployment needs a Unix management socket,
place it under an explicitly writable private directory and extend
`ReadWritePaths` in a local unit drop-in.

Validate unit syntax before installation:

```sh
systemd-analyze verify deploy/pooler.service deploy/pooler@.service
```

After installation, check the effective hardening and runtime state with
`systemctl show pooler.service` and `journalctl -u pooler.service`.

## Operational checks

Run `pooler preflight` for non-billable provider DNS, TLS, authentication, and
discovery checks. Keep its output and logs free of secret values. Management
read endpoints are available only when a `management.bind` is configured; a
remote bind is rejected until management TLS exists. For production, leave
management loopback-only unless the deployment adds a separately authenticated
and encrypted edge.
