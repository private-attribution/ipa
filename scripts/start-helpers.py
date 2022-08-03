import argparse
import subprocess
from select import select


def start_helpers(exec, count, port, timeout=0.1):
    commands = [
        [exec, '-vvv',  '-p', str(port + i)] for i in range(count)
    ]

    procs = [subprocess.Popen(cmd,
                              stdout=subprocess.PIPE,
                              bufsize=1,
                              universal_newlines=True,
                              ) for cmd in commands]

    while procs:
        for p in procs:
            # remove terminated processes
            if p.poll() is not None:
                print(p.stdout.read(), end='')
                p.stdout.close()
                procs.remove(p)

        # wait and print the output
        rlist = select([p.stdout for p in procs], [], [], timeout)[0]
        for f in rlist:
            print(f.readline(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Start multiple helpers serializing all outputs to stdout")

    parser.add_argument(
        '-t', '--timeout', type=float, metavar="SEC", default=0.1,
        help='specify the select timeout for sync',
    )
    parser.add_argument(
        '-e', '--executable', type=str, metavar="path", required=True, help="helper server executable path"
    )
    parser.add_argument(
        '-n', '--number', type=int, metavar="count", default=3, help="Number of helpers to start. Default = 3"
    )
    parser.add_argument(
        '-p', '--port', type=int, metavar="port", default=12345, help=(
            "Helper servers' starting port number. Default = 12345.\n"
            "E.g. \"-p 12345 -n 3\" will try to bind to 12345, 12346, 12347."
        )
    )

    # Handle the input from the command line
    try:
        args = parser.parse_args()
        start_helpers(exec=args.executable,
                      count=args.number,
                      port=args.port,
                      timeout=args.timeout,)
        parser.exit(0)
    except Exception as e:
        parser.error(str(e))
