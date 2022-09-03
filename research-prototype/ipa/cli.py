""" Interoperable Private Attribution - Research Prototype Aggregator using MP-SPDZ

Usage:
  ipa compile [--numrows_power=<n>] [--breakdown_values=<b>] [--n_bits=<n_bits>]
              [--radix_sort | --two_bit_radix_sort | --batcher_sort]
              [--sequential_capping] [--verbose_compile_filename]
              [--skip_sort] [--skip_attribution] [--skip_capping] [--skip_aggregation]
  ipa generate_input [--numrows_power=<n>] [--breakdown_values=<b>] [--n_bits=<n_bits>]
                     [--approx_rows_per_mk=<rmk>] [--valuemod=<vm>]
                     [--test_case_index=<tci>]

  --numrows_power=<n>         Run for 2^n input rows. [default: 4]
  --breakdown_values=<b>      Number of Breakdown keys. [default: 4]
  --n_bits=<n_bits>           Number of bits used for matchkeys. [default: 32]
  --radix_sort                Use radix_sort. default: library_sort
  --two_bit_radix_sort        Use two_bit_radix_sort. default: library_sort
  --batcher_sort              Use batcher_sorts (NOT IMPLEMENTED.) default: library_sort
  --sequential_capping        Use sequential_capping. default: paralell
  --verbose_compile_filename  Compiled filename reflects args.
  --skip_sort                 Skip the sort (for performance measurement.)
  --skip_attribution          Skip attribution (for performance measurement.)
  --skip_capping              Skip capping (for performance measurement.)
  --skip_aggregation          Skip aggregation (for performance measurement.)
  --approx_rows_per_mk=<rmk>  Approximate rows per matchkey. [default: 10]
  --valuemod=<vm>             Modulo used for values. [default: 256]
  --test_case_index=<tci>     Use a known test case. Otherwise random.
"""
from docopt import docopt
from schema import Schema, Use, Or, And
from sort import sort_functions


def parse_mutually_exclusive_options(args, options, new_arg_name, default=None):
    """
    Converts a dict <args> containing the keys in <options> and updates
    <args[new_arg_name]> to the exclusively true value in <options>.
    """
    selected_options = [k for k, v in args.items() if k in options and v]
    if not selected_options and default is None:
        raise Exception(f"One the following must be selected: {options}")
    elif len(selected_options) > 1:
        raise Exception(f"Can only select one of {selected_options}")
    for option in options:
        if option in args:
            del args[option]
    selected_options.append(default)
    args[new_arg_name] = selected_options[0]
    return args


def clean_args(args):
    """
    Remove "--" and upper case all keys in args.
    """
    return {k.strip("--").upper(): v for k, v in args.items()}


def validate_args(args):
    args = parse_mutually_exclusive_options(
        args,
        sort_functions.keys(),
        "SORT_FUNCTION_NAME",
        default="LIBRARY_SORT",
    )

    capping_types = ["SEQUENTIAL_CAPPING", "PARALLEL_CAPPING"]
    args = parse_mutually_exclusive_options(
        args,
        capping_types,
        "CAPPING_TYPE",
        default="PARALLEL_CAPPING",
    )
    schema = Schema(
        {
            "SORT_FUNCTION_NAME": Or(*sort_functions.keys()),
            "CAPPING_TYPE": Or(*capping_types),
            "NUMROWS_POWER": Use(int),
            "BREAKDOWN_VALUES": Use(int),
            "N_BITS": Use(int),
            "COMPILE": Use(bool),
            "VERBOSE_COMPILE_FILENAME": Use(bool),
            "SKIP_SORT": Use(bool),
            "SKIP_ATTRIBUTION": Use(bool),
            "SKIP_CAPPING": Use(bool),
            "SKIP_AGGREGATION": Use(bool),
            "GENERATE_INPUT": Use(bool),
            "APPROX_ROWS_PER_MK": Use(int),
            "VALUEMOD": Use(int),
            "TEST_CASE_INDEX": Or(None, And(Use(int), lambda n: 0 <= n < 2)),
        }
    )
    args = schema.validate(args)
    return args


def get_args():
    args = docopt(__doc__)
    args = clean_args(args)
    args = validate_args(args)
    return args
