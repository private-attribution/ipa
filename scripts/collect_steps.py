#!/usr/bin/env python3
import os
import re
import subprocess
import sys

# This script collects all the steps that are executed in the oneshot_ipa with
# all possible configurations.

IPA_ENV = [["RUST_LOG", "ipa=DEBUG"]]
ARGS = [
    "cargo",
    "bench",
    "--bench",
    "oneshot_ipa",
    "--no-default-features",
    "--features=enable-benches debug-trace step-trace",
    "--",
    "--num-multi-bits",
    "3",
]
QUERY_SIZE = 10
PER_USER_CAP = [1, 3]
ATTRIBUTION_WINDOW = [0, 86400]
BREAKDOWN_KEYS = [8, 33]
SECURITY_MODEL = ["malicious", "semi-honest"]
ROOT_STEP_PREFIX = "protocol/alloc::string::String::run-0"

DEPTH_DYNAMIC_STEPS = "ipa::protocol::attribution::InteractionPatternStep"
BIT_DYNAMIC_STEPS = [
    "ipa::protocol::attribution::aggregate_credit::Step::compute_equality_checks",
    "ipa::protocol::attribution::aggregate_credit::Step::check_times_credit",
]
MAXIMUM_DEPTH = 32
MAXIMUM_BIT_LENGTH = 32


def set_env():
    env = os.environ.copy()
    for k, v in IPA_ENV:
        env[k] = v
    return env


def remove_root_step_name_from_line(l):
    return l.split(",")[0][len(ROOT_STEP_PREFIX) + 1 :]


def to_int_or(s):
    try:
        return int(s)
    except ValueError:
        return s


def collect_steps(args):
    output = set()
    interaction_pattern_steps = set()
    compute_equality_checks_steps = set()

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

        if not line.startswith(ROOT_STEP_PREFIX):
            print("Unexpected line: " + line)
            exit(1)

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
        if any(s in line for s in DEPTH_DYNAMIC_STEPS):
            line = re.sub(r"depth\d+", "depthX", line)
            interaction_pattern_steps.add(remove_root_step_name_from_line(line))
            # continue without adding to the `output`. we'll generate the dynamic steps later
            continue
        # do the same for bit dynamic steps
        if any(s in line for s in BIT_DYNAMIC_STEPS):
            line = re.sub(r"bit\d+", "bitX", line)
            compute_equality_checks_steps.add(remove_root_step_name_from_line(line))
            continue

        output.update([remove_root_step_name_from_line(line)])
        count += 1

    # safeguard against empty output
    if count == 0:
        print("No steps in the output")
        exit(1)

    # generate dynamic steps
    for i in range(MAXIMUM_DEPTH):
        for s in interaction_pattern_steps:
            line = re.sub(r"depthX", "depth" + str(i), s)
            output.add(line)
    for i in range(MAXIMUM_BIT_LENGTH):
        for s in compute_equality_checks_steps:
            line = re.sub(r"bitX", "bit" + str(i), s)
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


if __name__ == "__main__":
    steps = set()
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
                    print(" ".join(args), file=sys.stderr)
                    steps.update(collect_steps(args))

    full_steps = extract_intermediate_steps(steps)
    sorted_steps = sorted(full_steps)

    for step in sorted_steps:
        print(step)
