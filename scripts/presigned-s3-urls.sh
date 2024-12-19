#!/bin/bash

# Set the usage message
usage="Usage: $0 <s3_uri> <output_file> [<expires_in_hours>]"

# Example invocation
# ../scripts/presigned-s3-urls.sh s3://stg-ipa-encrypted-reports/testing-sharded-data/1B/30_shards presigned_urls_30_shards.txt 168

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

# default expires_in: 7 days (7 * 24). this is the max allowed
expires_in_hours="${1:-168}"
expires_in=$((expires_in_hours* 3600 - 1))

if [ $# -gt 604799 ]; then
    echo "expires_in must be less than 168 hours"
    exit 1
fi

# Iterate over the files in the s3 bucket
aws s3 ls "$s3_uri" | awk '{print $4}' | while read -r line; do
# Skip directories (they end with a slash)
  if [[ "$line" != */ ]]; then
    echo "Processing: $(basename "$s3_uri""$line")"
    # Call the aws s3 presign command and append the output to the output file
    aws s3 presign "$s3_uri$line" --expires-in "$expires_in" >> "$output_file"
  fi
done
