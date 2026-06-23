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

# How OpenSSL is linked into the GNU builds (see build.zig). Accepts:
#   static  - bundle ~3MB of OpenSSL into every binary (default, self-contained)
#   shared  - build & ship one libssl.so.3/libcrypto.so.3 shared by all binaries
#             (much smaller, still self-contained, works cross-compiled)
#   system  - link the target's system OpenSSL (native builds only)
export OPENSSL := env("OPENSSL", "static")

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
# Only mosquitto 2.1.x+ build.zig files build the loadable plugins (and the
# GNU/glibc dynamically-linked broker needed to load them) and the extra CLI
# tools (mosquitto_pub/sub/rr/passwd/ctrl/db_dump/signal). Older versions only
# produce the broker binary, so we derive a musl-broker-only config from
# .goreleaser.yaml:
#   - drop every build/archive/nfpm whose id contains "gnu", and
#   - drop the CLI-tool package contents (src under zig-out/.../bin/mosquitto_*)
# so we never package artifacts that were never built. Outputs the config path
# on stdout. Detected via the buildPlugin helper, present only in the
# feature-rich build.zig files.
[private]
_config:
    #!/usr/bin/env bash
    set -euo pipefail
    has_plugins=false
    grep -q 'buildPlugin' "build/${VERSION}/build.zig" 2>/dev/null && has_plugins=true
    openssl_shared=false
    [ "${OPENSSL:-static}" = "shared" ] && openssl_shared=true

    # Full config only when this version builds plugins AND ships shared OpenSSL.
    if $has_plugins && $openssl_shared; then
        echo .goreleaser.yaml
        exit 0
    fi

    command -v yq >/dev/null 2>&1 || { echo "ERROR: yq is required to derive the goreleaser config" >&2; exit 1; }
    out=.goreleaser.generated.yaml
    # Use del(...|select(...)) rather than map() so YAML aliases elsewhere in the
    # contents/files lists are preserved (map() expands them and duplicates the
    # anchor definitions).
    expr='.'
    if ! $has_plugins; then
        # No plugins / GNU / CLI tools in this version: drop the gnu sections and
        # the CLI-tool package/archive contents.
        expr="${expr} |
          del(.builds[]   | select(.id | test(\"gnu\"))) |
          del(.archives[] | select(.id | test(\"gnu\"))) |
          del(.nfpms[]    | select(.id | test(\"gnu\"))) |
          del(.nfpms[].contents[]  | select((.src // \"\") | test(\"bin/mosquitto_\"))) |
          del(.archives[].files[]  | select((.src // \"\") | test(\"bin/mosquitto_\")))"
    fi
    if ! $openssl_shared; then
        # OpenSSL is not shipped as a shared lib: drop the libssl/libcrypto .so
        # contents (they are only produced when OPENSSL=shared).
        expr="${expr} |
          del(.nfpms[].contents[] | select((.src // \"\") | test(\"lib/lib(ssl|crypto)[.]so\"))) |
          del(.archives[].files[] | select((.src // \"\") | test(\"lib/lib(ssl|crypto)[.]so\")))"
    fi
    yq "${expr}" .goreleaser.yaml > "$out"
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
