#!/usr/bin/env bash

set -Eeuo pipefail

: "${RUNNER_TEMP:=${TMPDIR:-/tmp}}"

toolchain="${INPUT_TOOLCHAIN:-}"
components="${INPUT_COMPONENTS:-}"
targets="${INPUT_TARGETS:-}"

if [[ -z "$toolchain" ]]; then
  echo "setup-rust: toolchain input is required" >&2
  exit 2
fi

if [[ "$toolchain" == *$'\n'* || "$toolchain" == *$'\r'* ]]; then
  echo "setup-rust: toolchain input must be a single line" >&2
  exit 2
fi

if [[ "$RUNNER_TEMP" == *$'\n'* || "$RUNNER_TEMP" == *$'\r'* ]]; then
  echo "setup-rust: RUNNER_TEMP must be a single line" >&2
  exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "setup-rust: curl is required by the official rustup installer" >&2
  exit 1
fi

# RUNNER_TEMP is isolated by the runner for each job.  mktemp also keeps
# concurrent jobs safe when a custom runner reuses the same temp directory.
state_root="$(mktemp -d "$RUNNER_TEMP/pooler-rust.XXXXXX")"
cargo_home="$state_root/cargo"
rustup_home="$state_root/rustup"
mkdir -p "$cargo_home" "$rustup_home"

export CARGO_HOME="$cargo_home"
export RUSTUP_HOME="$rustup_home"
export PATH="$CARGO_HOME/bin:$PATH"
export RUSTUP_TOOLCHAIN="$toolchain"

rustup_init_url="https://sh.rustup.rs"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --retry 3 "$rustup_init_url" \
  | sh -s -- -y --no-modify-path --default-toolchain none --profile minimal

rustup="$CARGO_HOME/bin/rustup"
if [[ ! -x "$rustup" ]]; then
  echo "setup-rust: official rustup installer did not create $rustup" >&2
  exit 1
fi

split_csv() {
  local value="$1"
  local item
  local -a items

  [[ -n "$value" ]] || return 0
  IFS=',' read -r -a items <<< "$value"
  for item in "${items[@]}"; do
    # Inputs are normally compact (for example, clippy,rustfmt), but accept
    # a space after a comma without passing whitespace to rustup.
    item="${item#${item%%[![:space:]]*}}"
    item="${item%${item##*[![:space:]]}}"
    if [[ -z "$item" || "$item" == *$'\n'* || "$item" == *$'\r'* ]]; then
      echo "setup-rust: comma-separated inputs must contain non-empty values" >&2
      exit 2
    fi
    printf '%s\n' "$item"
  done
}

install_args=(toolchain install "$toolchain" --profile minimal --no-self-update)
while IFS= read -r component; do
  install_args+=(--component "$component")
done < <(split_csv "$components")
while IFS= read -r target; do
  install_args+=(--target "$target")
done < <(split_csv "$targets")

"$rustup" "${install_args[@]}"
"$rustup" default "$toolchain"

# Do not let a stale wrapper from the runner break cargo.  Preserve an
# explicitly configured executable wrapper, but publish an empty value when
# the inherited value is absent or invalid.
rustc_wrapper="${RUSTC_WRAPPER:-}"
if [[ -n "$rustc_wrapper" ]]; then
  if [[ "$rustc_wrapper" == */* ]]; then
    [[ -x "$rustc_wrapper" ]] || rustc_wrapper=""
  else
    wrapper_path="$(command -v "$rustc_wrapper" || true)"
    if [[ -z "$wrapper_path" || ! -x "$wrapper_path" ]]; then
      rustc_wrapper=""
    else
      rustc_wrapper="$wrapper_path"
    fi
  fi
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    printf 'CARGO_HOME=%s\n' "$CARGO_HOME"
    printf 'RUSTUP_HOME=%s\n' "$RUSTUP_HOME"
    printf 'RUSTUP_TOOLCHAIN=%s\n' "$RUSTUP_TOOLCHAIN"
    printf 'RUSTC_WRAPPER=%s\n' "$rustc_wrapper"
  } >> "$GITHUB_ENV"
fi
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$CARGO_HOME/bin" >> "$GITHUB_PATH"
fi

echo "setup-rust: installed $("$rustup" toolchain list | sed -n '1p')"
"$CARGO_HOME/bin/rustc" --version --verbose
