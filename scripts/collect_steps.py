import os
import re
import subprocess

# This script collects all the steps that are executed in the oneshot_ipa with
# all possible configurations.

IPA_ENV = [["RUST_LOG", "ipa=DEBUG"]]
CARGO = "cargo"
OPTIONS = [
    "cargo",
    "bench",
    "--bench",
    "oneshot_ipa",
    "--no-default-features",
    "--features=enable-benches debug-trace step-trace",
    "--",
    "--num-multi-bits",
    "1",
]
QUERY_SIZE = 10
PER_USER_CAP = [1, 3]
ATTRIBUTION_WINDOW = [0, 86400]
BREAKDOWN_KEYS = [1, 33]
SECURITY_MODEL = ["malicious", "semi-honest"]
ROOT_STEP_PREFIX = "protocol/alloc::string::String::run-0"
EXPECTED_HEADER_LINES_COUNT = 4


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


# Split string into list of strings and ints.
#
# E.g. "protocol/run-0/mc0/xor1" -> ["protocol/run-", 0, "/mc", 0, "/xor", 1]
#
# This is used to sort the steps in the natural order (e.g. 1, 2, 10, 11, 20).
def natural_sort_key(s):
    return [to_int_or(v) for v in re.split("(\d+)", s)]


def collect_steps(args):
    output = []

    proc = subprocess.Popen(
        executable=CARGO,
        args=args,
        env=set_env(),
        stdout=subprocess.PIPE,
        bufsize=1,
        universal_newlines=True,
    )

    count = 0
    header = 0
    while True:
        line = proc.stdout.readline()
        if not line or line == "":
            break

        if not line.startswith(ROOT_STEP_PREFIX):
            header += 1
            continue

        output.append(remove_root_step_name_from_line(line))
        count += 1

    # safeguard against empty output
    if count == 0:
        print("No steps in the output")
        exit(1)

    # oneshot_ipa produces 4 header lines
    if header != EXPECTED_HEADER_LINES_COUNT:
        print("Unexpected header lines in the output")
        exit(1)

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
    output = []
    for step in steps:
        substeps = step.split("/")
        for i in range(1, len(substeps)):
            output.append("/".join(substeps[:i]))
    steps.extend(output)


def remove_duplicates_and_sort(steps):
    # Converting a list to dict removes duplicates. We want a list for the sorting.
    unique_steps = list(dict.fromkeys(steps))

    # "natural" sort
    unique_steps.sort(key=natural_sort_key)

    # remove empty string if present
    try:
        unique_steps.remove("")
    except Exception:
        pass

    return unique_steps


if __name__ == "__main__":
    steps = []
    for c in PER_USER_CAP:
        for w in ATTRIBUTION_WINDOW:
            for b in BREAKDOWN_KEYS:
                for m in SECURITY_MODEL:
                    args = OPTIONS + [
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
                    steps.extend(collect_steps(args))

    extract_intermediate_steps(steps)
    steps = remove_duplicates_and_sort(steps)

    for step in steps:
        print(step)
