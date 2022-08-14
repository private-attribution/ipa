""" Interoperable Private Attribution - Research Prototype Aggregator using MP-SPDZ

Usage:
  ipa compile [--numrows_power=<n>] [--breakdown_values=<b>] [--n_bits=<n_bits>]
              [--radix_sort | --two_bit_radix_sort | --batcher_sort]
              [--sequential_capping] [--verbose_compile_filename]
              [--skip_sort] [--skip_attribution] [--skip_capping] [--skip_aggregation]


Options:
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
"""
from docopt import docopt
from schema import Schema, Use, Or

from ipae2e import (
    load_data,
    oblivious_attribution,
    sequential_capping,
    parallel_capping,
    aggregate,
)
from asort import sort_functions

from Compiler.compilerLib import Compiler
from Compiler.library import print_ln
from Compiler.types import Array, sint, sintbit


def parse_mutually_exclusive_options(args, options, new_arg_name, default=None):
    """
    Converts a dict <args> containing the keys in <options> and updates
    <args[new_arg_name]> to the exclusively true value in <options>.
    """
<<<<<<< Updated upstream
    selected_options = [
        k for k, v in args.items()
        if k in options and v
    ]
=======
    selected_options = [k for k, v in args.items() if k in options and v]
>>>>>>> Stashed changes
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
    args = clean_args(args)
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
        }
    )
    args = schema.validate(args)
    return args


def compiled_filename(args):
    filename = "ipae2e"
    keys_to_ignore = {"VERBOSE_COMPILE_FILENAME", "COMPILE"}
    if args["VERBOSE_COMPILE_FILENAME"]:
        for k, v in sorted(args.items()):
            if k not in keys_to_ignore:
                if type(v) == bool:
                    filename += f"___{k}"
                else:
                    filename += f"___{k}__{v}"
    return filename


def _compile(args):
    numrows = 2 ** args["NUMROWS_POWER"]
    sort_function = sort_functions[args["SORT_FUNCTION_NAME"]]
    capping_functions = {
        "SEQUENTIAL_CAPPING": sequential_capping,
        "PARALLEL_CAPPING": parallel_capping,
    }
    capping_function = capping_functions[args["CAPPING_TYPE"]]
    breakdown_values = args["BREAKDOWN_VALUES"]
    skip_sort = args["SKIP_SORT"]
    skip_attribution = args["SKIP_ATTRIBUTION"]
    skip_capping = args["SKIP_CAPPING"]
    skip_aggregation = args["SKIP_AGGREGATION"]

    compiler = Compiler(custom_args=["compile.py", "-C", "-R", "32"])

    filename = compiled_filename(args)
    print(f"Compiling {filename}")

    @compiler.register_function(filename)
    def ipae2e():
        # load the data
        reports, match_keys = load_data(numrows)

        if not skip_sort:
            # BUG: function calls like ths shouldn't have a side effect.
            # it should ether return back a new reports object, or be a
            # method on the reports object
            sort_function(match_keys, reports)

        if not skip_attribution:
            helperbits, final_credits = oblivious_attribution(
                reports,
                breakdown_values,
            )
        else:
            helperbits = Array(numrows, sintbit)
            helperbits.assign_all(0)
            final_credits = Array(numrows, sint)
            helperbits.assign_all(0)

        if not skip_capping:
            final_credits = capping_function(numrows, final_credits, helperbits)

        if not skip_aggregation:
            breakdown_key_sums = aggregate(reports, breakdown_values, final_credits)
            print_ln("breakdowns: %s", breakdown_key_sums.reveal())

    compiler.compile_func()


def main():
    args = docopt(__doc__)
    args = validate_args(args)

    if args["COMPILE"]:
        _compile(args)


if __name__ == "__main__":
    main()
