#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
version="${CHECKIN_BUILD_VERSION:-}"
output_dir="${CHECKIN_BUILD_OUTPUT:-$repo_root/dist/go}"
targets=(windows-amd64 linux-amd64 linux-arm64)

usage() {
  cat <<'USAGE'
Usage: bash scripts/build-go.sh [--version VERSION] [--output DIR] [TARGET ...]
Targets: windows-amd64 linux-amd64 linux-arm64 (all by default)
Windows includes silent checkin.exe and console checkin-cli.exe.
The output directory contains SHA256SUMS for this invocation's binaries.
USAGE
}

selected_targets=()
while (($#)); do
  case "$1" in
    --version|--output)
      if (($# < 2)); then printf 'Missing value for %s\n' "$1" >&2; exit 2; fi
      if [[ "$1" == --version ]]; then version="$2"; else output_dir="$2"; fi
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    windows-amd64|linux-amd64|linux-arm64) selected_targets+=("$1"); shift ;;
    *) printf 'Unknown build option or target: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done
if ((${#selected_targets[@]})); then targets=("${selected_targets[@]}"); fi
if ! command -v go >/dev/null 2>&1; then printf 'Go 1.26.10 or later is required.\n' >&2; exit 1; fi
if [[ -z "$version" ]]; then
  version="$(git -C "$repo_root" describe --tags --always --dirty 2>/dev/null || printf dev)"
fi
if [[ ! "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$ ]]; then
  printf 'Invalid version. Use 1..128 ASCII letters, numbers, dots, underscores, pluses or hyphens.\n' >&2
  exit 2
fi
mkdir -p -- "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd)"
artifacts=()
cd -- "$repo_root"
CGO_ENABLED=0 GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" \
  go run -mod=readonly ./scripts/license-notices --out "$output_dir/GO_DEPENDENCY_LICENSES.txt"
cp -- LICENSE THIRD_PARTY_NOTICES.md "$output_dir/"
cp -- docs/go-edition.md "$output_dir/README.md"
for target in "${targets[@]}"; do
  target_os="${target%-*}"
  target_arch="${target#*-}"
  target_dir="$output_dir/$target"
  mkdir -p -- "$target_dir"
  base_flags="-s -w -X=main.version=$version"
  if [[ "$target_os" == windows ]]; then
    printf 'Building %s/checkin.exe (silent)\n' "$target"
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
      go build -mod=readonly -p 1 -trimpath -buildvcs=false -ldflags "$base_flags -H=windowsgui" -o "$target_dir/checkin.exe" ./cmd/checkin
    artifacts+=("$target/checkin.exe")
    printf 'Building %s/checkin-cli.exe (console)\n' "$target"
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
      go build -mod=readonly -p 1 -trimpath -buildvcs=false -ldflags "$base_flags" -o "$target_dir/checkin-cli.exe" ./cmd/checkin
    artifacts+=("$target/checkin-cli.exe")
  else
    printf 'Building %s/checkin\n' "$target"
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
      go build -mod=readonly -p 1 -trimpath -buildvcs=false -ldflags "$base_flags" -o "$target_dir/checkin" ./cmd/checkin
    artifacts+=("$target/checkin")
  fi
done

# Checksum tools run from the output directory so paths work after copying it.
(
  cd -- "$output_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' "${artifacts[@]}" | LC_ALL=C sort -u | while IFS= read -r artifact; do sha256sum -- "$artifact"; done
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s\n' "${artifacts[@]}" | LC_ALL=C sort -u | while IFS= read -r artifact; do shasum -a 256 -- "$artifact"; done
  else
    printf 'A SHA256 tool (sha256sum or shasum) is required.\n' >&2
    exit 1
  fi
) > "$output_dir/SHA256SUMS"
printf 'Built CheckinMyFreeAPI %s. Output: %s\n' "$version" "$output_dir"
