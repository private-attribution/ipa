#!/usr/bin/env python3
import subprocess
import sys

# This script runs IPA oneshot with all possible combinations of the given
# parameters to make sure that Compact gate works correctly.

ARGS = [
    "cargo",
    "bench",
    "--bench",
    "oneshot_ipa",
    "--no-default-features",
    "--features=enable-benches compact-gate",
    "--",
    "--num-multi-bits",
    "3",
]
QUERY_SIZE = 10
PER_USER_CAP = [1, 10]
ATTRIBUTION_WINDOW = [0, 86400]
# breakdown_keys = [1..32] runs an optimized protocol, and the steps generated
# depend on the number of bits in the breakdown key. >= 33 runs a general protocol.
# As of July 2023, we are limiting the number of breakdown keys to 32.
BREAKDOWN_KEYS = [32]
SECURITY_MODEL = ["malicious", "semi-honest"]


def run(args):
    try:
        subprocess.check_output(
            args=args,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError as e:
        return False


if __name__ == "__main__":
    total = (
        len(PER_USER_CAP)
        * len(ATTRIBUTION_WINDOW)
        * len(BREAKDOWN_KEYS)
        * len(SECURITY_MODEL)
    )
    results = 0
    ng_results = 0
    ng_args = set()

    for c in PER_USER_CAP:
        for w in ATTRIBUTION_WINDOW:
            for b in BREAKDOWN_KEYS:
                for m in SECURITY_MODEL:
                    args = ARGS + [
                        "-n",
                        str(QUERY_SIZE),
                        "-c",
                        str(c),
                        "-w",
                        str(w),
                        "-b",
                        str(b),
                        "-m",
                        m,
                    ]
                    results += 1
                    print(f"  Running {results}/{total}", end="\r", flush=True)
                    if not run(args):
                        ng_results += 1
                        ng_args.add(" ".join(args))

    print()
    print(f"Success: {results - ng_results}")
    print(f"Failure: {ng_results}")
    if ng_results:
        print("Failed args:")
        for a in ng_args:
            print(a)
        exit(1)
