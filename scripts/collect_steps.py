#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys

# This script collects all the steps that are executed in the oneshot_ipa with
# all possible configurations.

IPA_ENV = [["RUST_LOG", "WARN,ipa_core::test_fixture::metrics=DEBUG"]]
QUERY_SIZE = 100
# attribution_window_seconds = 0 runs an optimized protocol, so 0 and anything larger
ATTRIBUTION_WINDOW = [0, 86400]
ROOT_STEP_PREFIX = "protocol/ipa_core::test_fixture::world::TestExecutionStep::iter0"
BREAKDOWN_KEYS = 256
USER_CAP = [8, 16, 32, 64, 128]
SECURITY_MODEL = "semi-honest"
TRIGGER_VALUES = [6, 7]

# TODO(taikiy): #771 allows us to remove this synthetic step generation code

# There are protocols in IPA that that will generate log(N) steps where N is the number
# of input rows to IPA. In this script, we execute IPA with 10 input rows, hence it
# only generates log2(10) (maybe a few more/less because of the optimizations) dynamic
# steps. Our goal is to generate 32 sets of these steps. (32 > log2(1B))
# We do this by replacing all "depth\d+" in the steps with "depthX", store them in the
# set, and later replace X with the depth of the iteration [0..32). We do that because
# there are more optimizations done at row index level (i.e., skip the multiplication
# for the last row), so the number of sub-steps branching off at each depth may differ.
# To workaround this issue, we do the "depthX" replacement and collect all possible
# steps and sub-steps (log2(10) steps should be enough to generate all possible
# combinations). That means the generated `Compact` gate code will contain state
# transitions that are not actually executed. This is not optimal, but not a big deal.
# It's impossible to generate the exact set of steps that are executed in the actual
# protocol without executing the protocol or analyzing the code statically.
DEPTH_DYNAMIC_STEPS = [
    "ipa_core::protocol::attribution::InteractionPatternStep",
]
MAXIMUM_DEPTH = 32


def set_env():
    env = os.environ.copy()
    for k, v in IPA_ENV:
        env[k] = v
    return env


def remove_root_step_name_from_line(l):
    return l.split(",")[0][len(ROOT_STEP_PREFIX) + 1 :]


def collect_steps(args):
    output = set()
    depth_dynamic_steps = set()

    proc = subprocess.Popen(
        args=args,
        env=set_env(),
        stdout=subprocess.PIPE,
        bufsize=1,
        universal_newlines=True,
    )

    count = 0
    while True:
        line = proc.stdout.readline()

        if not line or line == "":
            break

        if line.startswith("TestWorld random seed "):
            continue

        if not line.startswith(ROOT_STEP_PREFIX):
            print("Unexpected line: " + line, flush=True)
            exit(1)

        count += 1

        if any(s in line for s in DEPTH_DYNAMIC_STEPS):
            line = re.sub(r"depth\d+", "depthX", line)
            depth_dynamic_steps.add(remove_root_step_name_from_line(line))
            # continue without adding to the `output`. we'll generate the dynamic steps later
            continue

        output.update([remove_root_step_name_from_line(line)])

    # safeguard against empty output
    if count == 0:
        print("No steps in the output", flush=True)
        exit(1)

    # generate dynamic steps
    for i in range(MAXIMUM_DEPTH):
        for s in depth_dynamic_steps:
            line = re.sub(r"depthX", "depth" + str(i), s)
            output.add(line)

    return output


# Splits a line by "/" and create a vector consisting each splitted string
# concatenated by all the preceding strings.
#
# # Example
# input = "mod_conv_match_key/mc0/mc0/xor1"
# output = ["mod_conv_match_key",
#           "mod_conv_match_key/mc0",
#           "mod_conv_match_key/mc0/mc0",
#           "mod_conv_match_key/mc0/mc0/xor1"]
#
# We do this because not all substeps invoke communications between helpers.
#
# For example, a leaf substep "mod_conv_match_key/mc0/mc0/xor1" invokes
# multiplications, but "mod_conv_match_key/mc0/mc0" and "mod_conv_match_key/mc0"
# do not. However, we want to include these intermediate substeps in the output
# since each `narrow`, even if it doesn't actually do anything, is a state
# transition.
#
# This function generates a lot of duplicates. It is inefficient but we don't
# really care because we execute this script only once when we add a new
# protocol which is a pretty rare case. The duplicates will be removed in the
# `remove_duplicates_and_sort`.
def extract_intermediate_steps(steps):
    output = set()
    for step in steps:
        substeps = step.split("/")
        for i in range(1, len(substeps)):
            output.add("/".join(substeps[:i]))
    steps.update(output)

    # remove empty string if present
    try:
        steps.remove("")
    except Exception:
        pass

    return steps


def ipa_steps(base_args):
    output = set()
    for c in USER_CAP:
        for w in ATTRIBUTION_WINDOW:
            for tv in TRIGGER_VALUES:
                args = base_args + [
                    "-n",
                    str(QUERY_SIZE),
                    "-c",
                    str(c),
                    "-w",
                    str(w),
                    "-b",
                    str(BREAKDOWN_KEYS),
                    "-m",
                    SECURITY_MODEL,
                    "-t",
                    str(tv),
                ]
            print(" ".join(args), file=sys.stderr)
            output.update(collect_steps(args))
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate steps file")
    parser.add_argument(
        "-m",
        "--multi-threading",
        action="store_true",
    )
    args = parser.parse_args()

    features = ["enable-benches", "debug-trace", "step-trace"]
    if args.multi_threading:
        features.append("multi-threading")

    ARGS = [
        "cargo",
        "bench",
        "--bench",
        "oneshot_ipa",
        "--no-default-features",
        f'--features={" ".join(features)}',
        "--",
        "--num-multi-bits",
        "3",
    ]

    steps = set()
    steps.update(ipa_steps(ARGS))

    full_steps = extract_intermediate_steps(steps)
    sorted_steps = sorted(full_steps)

    for step in sorted_steps:
        print(step)
