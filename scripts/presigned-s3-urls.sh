#!/bin/bash

# Set the usage message
usage="Usage: $0 <dir_path> <s3_uri> <output_file>"

# Example invocation
# from ipa/input_data_S02/
# ../scripts/presigned-s3-urls.sh encryptions/1B_cat/30_shards/ s3://stg-ipa-encrypted-reports/testing-sharded-data/1B/30_shards presigned_urls_30_shards.txt

# Check if the correct number of arguments were provided
if [ $# -ne 3 ]; then
  echo "$usage"
  exit 1
fi

# Set the directory path and S3 URI from the command-line arguments
dir_path="$1"
s3_uri="$2"
output_file="$3"

# Iterate over the files in the directory
for file in "$dir_path"/*; do
  # Get the file name without the directory path
  filename=$(basename "$file")
  echo "Processing: $(basename "$file")"
  # Call the aws s3 presign command and append the output to the output file
  # expires in 7 days (7 * 24 * 60 * 60) - 1. this is the max allowed
  aws s3 presign "$s3_uri/$filename" --expires-in 604799 >> "$output_file"
done
