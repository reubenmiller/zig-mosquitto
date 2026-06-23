set dotenv-load

# package name
export PACKAGE_NAME := env("PACKAGE_NAME", if WITH_TLS == "true" { "tedge-mosquitto" } else { "tedge-mosquitto-notls" })

# package version
export VERSION := env("VERSION", "2.0.22")

# package version release suffix
export REVISION := env("REVISION", "1")

# output directory for the linux packages
OUTPUT_DIR := "dist"

# build mosquitto with tls. Accepts either 'true' or 'false'
export WITH_TLS := env("WITH_TLS", "true")

# list supported mosquitto versions
list-versions:
    @echo "The following mosquitto versions are supported:"
    @echo
    @ls -c1 build | xargs printf ' * %s\n'
    @echo
    @echo "Reference one of the above versions to build mosquitto:"
    @echo
    @echo "  just VERSION=2.0.18 build"
    @echo

# Resolve the goreleaser config to use for the current VERSION.
# Only mosquitto versions whose build.zig builds loadable plugins (2.1.x+) get the
# GNU/glibc (dynamically linked) builds and plugin packaging. Older versions only
# produce the broker binary, so we derive a musl-only config from .goreleaser.yaml
# (stripping every build/archive/nfpm whose id contains "gnu") to avoid packaging
# plugin .so files that were never built. Outputs the config path on stdout.
[private]
_config:
    #!/usr/bin/env bash
    set -euo pipefail
    if grep -q 'buildPlugin' "build/${VERSION}/build.zig" 2>/dev/null; then
        echo .goreleaser.yaml
        exit 0
    fi
    command -v yq >/dev/null 2>&1 || { echo "ERROR: yq is required to package mosquitto versions without plugins" >&2; exit 1; }
    out=.goreleaser.generated.yaml
    yq '
      del(.builds[]   | select(.id | test("gnu"))) |
      del(.archives[] | select(.id | test("gnu"))) |
      del(.nfpms[]    | select(.id | test("gnu")))
    ' .goreleaser.yaml > "$out"
    echo "$out"

# Note: use --parallelism 1 due to a problem when running builds in parallel, most likely
# caused by the openssl dependency
[private]
_release *ARGS='':
    #!/usr/bin/env bash
    set -euo pipefail
    config="$(just _config)"
    GORELEASER_CURRENT_TAG={{VERSION}} REVISION={{REVISION}} WITH_TLS={{WITH_TLS}} PACKAGE_NAME="{{PACKAGE_NAME}}" goreleaser release --config "$config" --parallelism 1 --auto-snapshot --skip=announce,publish,validate --clean {{ARGS}}

[private]
_build *ARGS='':
    #!/usr/bin/env bash
    set -euo pipefail
    config="$(just _config)"
    GORELEASER_CURRENT_TAG={{VERSION}} REVISION={{REVISION}} WITH_TLS={{WITH_TLS}} PACKAGE_NAME="{{PACKAGE_NAME}}" goreleaser build --config "$config" --parallelism 1 --auto-snapshot --clean {{ARGS}}

# build the binary with tls enabled (default)
build *ARGS='':
    WITH_TLS=true just _release

build-target TARGET *ARGS='':
    TARGET={{TARGET}} just _build --single-target

# build using native zig command (to help with debugging)
build-native *ARGS='':
    cd build/{{VERSION}} && zig build --release=small -Doptimize=ReleaseSmall -DWITH_TLS={{WITH_TLS}} {{ARGS}}
    @echo
    @echo "Build OK. Execute the binary using"
    @echo ""
    @echo "  ./build/{{VERSION}}/zig-out/bin/mosquitto"
    @echo

# clean the distribution folders
clean:
    rm -rf {{OUTPUT_DIR}}

# Publish packages
publish *args="":
    ./ci/publish.sh --path "{{OUTPUT_DIR}}" {{args}}
