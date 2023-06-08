#!/usr/bin/env bash

set -eou pipefail

help() {
  echo "Usage: $0 --hostname [hostname] --identity [1|2|3] --platform [platform]"
  echo "- hostname: public hostname that will appear on TLS certificate"
  echo "- identity: helper identity to be fixed inside the IPA build"
  echo "- platform: the platform for the helper image, defaults to linux/amd64"
}

platform="linux/amd64"

parse_args() {
  while [ "${1:-}" != "" ]; do
    case "$1" in
      --identity)
        shift
        identity="$1"
        ;;
      --hostname)
        shift
        hostname="$1"
        ;;
      --platform)
        shift
        platform="$1"
        ;;
      *)
      # unknown option
      help
      exit 1
    esac
    shift
  done
}

parse_args "$@"
if [[ -z "${identity}" || -z "${hostname}" ]]; then
    help
    exit 1
fi

rev=$(git log -n 1 --format='format:%H' | cut -c1-10)
tag="private-attribution/ipa:$rev-h$identity"

cd "$(dirname "$0")"/.. || exit 1

# Docker can only pick up .dockerignore from the root folder (see https://github.com/moby/moby/issues/12886).
# Use tar to create the build context manually before sending it to Docker CLI
tar -cvzf - --exclude-from="docker/.dockerignore" ./* \
  | docker build \
    -t "$tag" \
    -f docker/helper.Dockerfile \
    --platform "$platform" \
    --progress=plain --no-cache \
    --build-arg IDENTITY="$identity" \
    --build-arg HOSTNAME="$hostname" -
