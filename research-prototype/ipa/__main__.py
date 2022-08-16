from cli import get_args
from _compile import _compile
from generate_input import generate_input_from_args

if __name__ == "__main__":
    args = get_args()

    if args["COMPILE"]:
        _compile(args)
    elif args["GENERATE_INPUT"]:
        generate_input_from_args(args)
