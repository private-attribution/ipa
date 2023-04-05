#!/usr/bin/env bash
#
# Generate test coverage reports.
#
# To use, point this at the files you want a coverage report on.  This opens a
# browser with a report or point you at the report if it can't find a browser.
#
# You will need a few tools installed, but this script should be able to install
# those for you using `rustup` or `cargo`.

set -e

tests=()
index="."
for a in "$@"; do
    if [[ -e "$a" ]]; then
        for f in $(find "$a" -name '*.rs' -type f -exec realpath --relative-to="$(dirname "$0")/../src" {} \+); do
            if [[ "$index" == "." ]]; then
                index="coverage/$(realpath "$a")"
            else
                index="index"
            fi
            f="${f//\//::}"
            tests+=("${f%.rs}")
        done
    fi
done
[[ "$index" == "." ]] && index="index"

cd "$(dirname "$0")/.."


if ! hash llvm-profdata || ! hash llvm-cov; then
    echo "Installing llvm-tools component using rustup..."
    rustup component add llvm-tools-preview
fi
if ! hash rustfilt; then
    echo "Installing rustfilt using cargo..."
    cargo install rustfilt
fi

for i in llvm-profdata llvm-cov rustfilt; do
    if ! hash "$i"; then
        echo "Unable to install '$i'" 1>&2
        exit 2
    fi
done

if hash wslview; then
    open=(wslview)
elif hash xdg-open; then
    open=(xdg-open)
else
    open=(echo "Report saved at ")
fi

profdir="$(mktemp -d /tmp/coverage-XXXXX)"
profdata="$profdir/coverage.profdata"
echo "Running 'cargo test -- ${tests[@]}"
RUSTFLAGS="-C instrument-coverage" \
LLVM_PROFILE_FILE="$profdir/coverage-%m-%p.profraw" \
    cargo test --lib -- "${tests[@]}"

echo "Generating profiling data"
llvm-profdata merge -sparse -o "$profdata" "$profdir"/*.profraw

echo "Generating HTML report in $profdir"
test_binary="$(ls -td -I '*.*' ./target/debug/deps/ipa-* | head -1)"
llvm-cov show -Xdemangler=rustfilt "$test_binary" -instr-profile="$profdata" \
    -show-line-counts-or-regions -show-instantiations \
    -ignore-filename-regex="/\.cargo/registry/" \
    -format=html -output-dir="$profdir"

"${open[@]}" "${profdir}/${index}.html"
