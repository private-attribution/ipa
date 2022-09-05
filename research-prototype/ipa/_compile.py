from ipae2e import (
    load_data,
    oblivious_attribution,
    sequential_capping,
    parallel_capping,
    aggregate,
)
from sort import sort_functions

from Compiler.compilerLib import Compiler
from Compiler.library import print_ln
from Compiler.types import Array, sint, sintbit


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
            aggregate_results = aggregate(reports, breakdown_values, final_credits)
            print_ln('{"breakdown_keys": %s}', aggregate_results.reveal())

    compiler.compile_func()
