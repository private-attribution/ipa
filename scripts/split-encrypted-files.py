import argparse
import binascii
import os

try:
    from tqdm import tqdm
except ImportError:
    print("tqdm not installed. run `pip install tqdm` to see progress")

    def tqdm(iterable, *args, **kwargs):
        return iterable


def split_hex_file(input_filename, output_stem, num_files):
    """
    Reads in a file of hex strings, one per line, splits it up into N files,
    and writes out each line as length-delimited binary data.

    :param input_filename: The name of the input file containing hex strings.
    :param num_files: The number of output files to split the input into.
    """
    output_files = [
        open(f"{output_stem}_shard_{i:03d}.bin", "wb") for i in range(num_files)
    ]

    input_filesize = os.path.getsize(input_filename)
    # estimation each line is about 250 bits
    approx_row_count = input_filesize / 250
    with open(input_filename, "r") as input_file:
        for i, line in enumerate(
            tqdm(input_file, desc="Processing lines", total=approx_row_count)
        ):
            # Remove any leading or trailing whitespace from the line
            line = line.strip()

            # Convert the hex string to bytes
            data = binascii.unhexlify(line)

            # Write the length of the data as a 2-byte integer (big-endian)
            output_files[i % num_files].write(len(data).to_bytes(2, byteorder="little"))

            # Write the data itself
            output_files[i % num_files].write(data)

    for f in output_files:
        f.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Splits a file of hex strings into N length-delimited binary files"
    )
    parser.add_argument(
        "-i", "--input_file", required=True, help="Input file containing hex strings"
    )
    parser.add_argument(
        "-o",
        "--output_stem",
        required=True,
        help="Output file stem for generated files",
    )
    parser.add_argument(
        "-n",
        "--num-files",
        type=int,
        required=True,
        help="Number of output files to split the input into",
    )
    args = parser.parse_args()

    split_hex_file(args.input_file, args.output_stem, args.num_files)
