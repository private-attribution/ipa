import argparse
import random
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Generate random IPA input data for MP-SPDZ"
)
parser.add_argument("numrows_power", type=int, help="Generate 2^n inputs")

args = parser.parse_args()

numrows = 2**args.numrows_power
approx_rows_per_mk = 10

modulus = 2**64
mkmod = 2**31
datamod = 2**8
breakdown_keys = 4

player_data = Path("Player-Data")
player_data.mkdir(parents=True, exist_ok=True)

with open(player_data / "Input-P0-0", "w") as f:
    separator = " "

    f.write(f"1" + separator + "1" + separator + "5" + separator + "0\n")
    f.write(f"1" + separator + "0" + separator + "0" + separator + "1\n")
    f.write(f"1" + separator + "1" + separator + "7" + separator + "0\n")

    f.write(f"2" + separator + "0" + separator + "0" + separator + "2\n")
    f.write(f"2" + separator + "1" + separator + "6" + separator + "0\n")
    f.write(f"2" + separator + "1" + separator + "8" + separator + "0\n")
    
    f.write(f"3" + separator + "0" + separator + "0" + separator + "1\n")
    f.write(f"3" + separator + "1" + separator + "3" + separator + "0\n")


    
    for i in range(8,numrows):
    	f.write(f"0"+separator +"0"+separator+"0"+separator +"0\n" )


print(f"wrote {numrows} rows")
print(f"output should be breakdown 1: 10, breakdown 2: 14, breakdown 3: 0")




