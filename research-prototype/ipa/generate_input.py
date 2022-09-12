import random
from pathlib import Path
from collections import namedtuple
from itertools import islice
import csv


TestReport = namedtuple(
    "TestReport",
    ["match_key", "is_trigger", "value", "breakdown_key"],
)

test_cases = [
    [
        TestReport(match_key=3, is_trigger=0, value=0, breakdown_key=1),
        TestReport(match_key=3, is_trigger=1, value=11, breakdown_key=0),
        TestReport(match_key=2, is_trigger=1, value=7, breakdown_key=0),
        TestReport(match_key=2, is_trigger=0, value=0, breakdown_key=2),
        TestReport(match_key=4, is_trigger=0, value=0, breakdown_key=3),
        TestReport(match_key=4, is_trigger=1, value=8, breakdown_key=0),
        TestReport(match_key=4, is_trigger=1, value=6, breakdown_key=0),
    ],
    [
        TestReport(match_key=1, is_trigger=1, value=5, breakdown_key=0),
        TestReport(match_key=1, is_trigger=0, value=0, breakdown_key=1),
        TestReport(match_key=1, is_trigger=1, value=7, breakdown_key=0),
        TestReport(match_key=2, is_trigger=0, value=0, breakdown_key=2),
        TestReport(match_key=2, is_trigger=1, value=6, breakdown_key=0),
        TestReport(match_key=2, is_trigger=1, value=8, breakdown_key=0),
        TestReport(match_key=3, is_trigger=0, value=0, breakdown_key=1),
        TestReport(match_key=3, is_trigger=1, value=3, breakdown_key=0),
    ],
]

test_cases_expected_results = [
    [11, 0, 14, 0],
    [10, 14, 0, 0],
]


def gen_test_case_reports(test_case):
    for test_report in test_case:
        yield test_report
    while True:
        yield TestReport(match_key=0, is_trigger=0, value=0, breakdown_key=0)


def gen_random_test_reports(numrows, approx_rows_per_mk, valuemod, breakdown_values):
    while True:
        match_key = random.randint(0, numrows // approx_rows_per_mk)
        is_trigger = random.randint(0, 1)
        if is_trigger:
            value, breakdown_key = random.randint(0, valuemod - 1), -1
        else:
            value, breakdown_key = 0, random.randint(0, breakdown_values - 1)
        yield TestReport(
            match_key=match_key,
            is_trigger=is_trigger,
            value=value,
            breakdown_key=breakdown_key,
        )


def generate_input(
    numrows_power,
    approx_rows_per_mk,
    valuemod,
    breakdown_values,
    n_bits,
    test_case_index=None,
):
    numrows = 2**numrows_power
    max_matchkey_values = numrows // approx_rows_per_mk

    if max_matchkey_values > 2**n_bits:
        raise Exception(
            f"Cannot generate {max_matchkey_values} distinct "
            "matchkeys with {n_bits} bits."
        )

    if test_case_index is None:
        test_reports = gen_random_test_reports(
            numrows, approx_rows_per_mk, valuemod, breakdown_values
        )
    else:
        test_case = test_cases[test_case_index]
        test_reports = gen_test_case_reports(test_case)

    player_data = Path("Player-Data")
    player_data.mkdir(parents=True, exist_ok=True)

    with open(player_data / "Input-P0-0", "w") as f:
        player_data_writer = csv.writer(f, delimiter=" ")
        for test_report in islice(test_reports, numrows):
            player_data_writer.writerow(
                (
                    test_report.match_key,
                    test_report.is_trigger,
                    test_report.value,
                    test_report.breakdown_key,
                )
            )

    print(f"wrote {numrows} rows")
    if test_case_index is not False:
        print(f"expected results: {test_cases_expected_results[test_case_index]}")


def generate_input_from_args(args):
    return generate_input(
        numrows_power=args["NUMROWS_POWER"],
        approx_rows_per_mk=args["APPROX_ROWS_PER_MK"],
        valuemod=args["VALUEMOD"],
        breakdown_values=args["BREAKDOWN_VALUES"],
        n_bits=args["N_BITS"],
        test_case_index=args["TEST_CASE_INDEX"],
    )
