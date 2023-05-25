#!/usr/bin/env bash

help() {
  echo "Usage: $0 --hostname [hostname] --identity [1|2|3]"
  echo "- hostname: public hostname that will appear on TLS certificate"
  echo "- identity: helper identity to be fixed inside the IPA build"
}

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

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$branch" == "main" ]]; then
  tag="private-attribution/ipa:latest"
else
  tag="private-attribution/ipa:${branch}"
fi

cd "$(dirname "$0")"/.. || exit 1
docker build -t "$tag" -f docker/helper.Dockerfile --build-arg IDENTITY="$identity" --build-arg HOSTNAME="$hostname" .
