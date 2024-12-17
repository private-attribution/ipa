import argparse
import binascii


def split_hex_file(input_filename, num_files):
    """
    Reads in a file of hex strings, one per line, splits it up into N files,
    and writes out each line as length-delimited binary data.

    :param input_filename: The name of the input file containing hex strings.
    :param num_files: The number of output files to split the input into.
    """
    output_files = [open(f"{input_filename}_{i}.bin", "wb") for i in range(num_files)]

    with open(input_filename, "r") as input_file:
        for i, line in enumerate(input_file):
            # Remove any leading or trailing whitespace from the line
            line = line.strip()

            # Convert the hex string to bytes
            data = binascii.unhexlify(line)

            # Write the length of the data as a 2-byte integer (big-endian)
            output_files[i % num_files].write(len(data).to_bytes(2, byteorder="big"))

            # Write the data itself
            output_files[i % num_files].write(data)

    for f in output_files:
        f.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Splits a file of hex strings into N length-delimited binary files"
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Input file containing hex strings"
    )
    parser.add_argument(
        "-n",
        "--num-files",
        type=int,
        required=True,
        help="Number of output files to split the input into",
    )
    args = parser.parse_args()

    split_hex_file(args.input, args.num_files)
