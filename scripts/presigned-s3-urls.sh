#!/bin/bash

# Set the usage message
usage="Usage: $0 <s3_uri> <output_file> [<expires_in>]"

# Example invocation
# ../scripts/presigned-s3-urls.sh s3://stg-ipa-encrypted-reports/testing-sharded-data/1B/30_shards presigned_urls_30_shards.txt

# Check if the correct number of arguments were provided
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  echo "$usage"
  exit 1
fi

# Set and validate the S3 URI, output_file, and expires_in from the command-line arguments
s3_uri="$1"
output_file="$2"
# Check if the output file already exists
if [ -f "$output_file" ]; then
  echo "Error: Output file '$output_file' already exists. Please remove it before running this script."
  exit 1
fi

# default expires_in: 7 days (7 * 24 * 60 * 60) - 1. this is the max allowed
expires_in="${3:-604799}"
if [ $# -gt 604799 ]; then
    echo "expires_in must be less than 604800"
    exit 1
fi

# Iterate over the files in the s3 bucket
while IFS= read -r line; do
  # Extract the file name from the aws s3 ls output
  filename=$(echo "$line" | awk '{print $NF}')

# Skip directories (they end with a slash)
  if [[ "$filename" != */ ]]; then
    echo "Processing: $(basename "$filename")"
    # Call the aws s3 presign command and append the output to the output file
    aws s3 presign "$s3_uri/$filename" --expires-in "$expires_in" >> "$output_file"
  fi
done < <(aws s3 ls "$s3_url" | awk '{print $4}')
