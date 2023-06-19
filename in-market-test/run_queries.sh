#!/bin/bash
IPA_REPO=$1
NETWORK_TOML=$2

query_sizes=(100 200 300)

# Define the arrays
attribution_windows=(86400 604800)
user_cappings=(1 2 3 4)
breakdown_keys=(32 64)

DATA_PATH=~/SyntheticTest/inputs
LOGS_PATH=~/SyntheticTest/logs


mkdir -p $DATA_PATH
mkdir -p $LOGS_PATH

echo "Generating input data"
cd $IPA_REPO
for (( n=0; n<${#query_sizes[@]}; n++ )); do
  cargo run --bin report_collector --features="cli test-fixture" -- gen-ipa-inputs -n ${query_sizes[$n]} --output-file $DATA_PATH/ipa-events-${query_sizes[$n]}.txt
done

echo "Running tests"
for (( n=0; n<${#query_sizes[@]}; n++ )); do
  for (( i=0; i<${#attribution_windows[@]}; i++ )); do
    for (( j=0; j<${#user_cappings[@]}; j++ )); do
      for (( k=0; k<${#breakdown_keys[@]}; k++ )); do
         echo "Running test for query_size=${query_sizes[$n]} attribution_window=${attribution_windows[$i]} user_capping=${user_cappings[$j]} breakdown_key=${breakdown_keys[$k]}"

         LOGFILE="${LOGS_PATH}/${query_sizes[$n]}_${attribution_windows[$i]}_${user_cappings[$j]}_${breakdown_keys[$k]}.log"

         cargo run --bin report_collector --features="cli test-fixture" -- --network $NETWORK_TOML --input-file $DATA_PATH/ipa-events-${query_sizes[$n]}.txt \
         --field fp32-bit-prime malicious-ipa --max-breakdown-key ${breakdown_keys[$k]} \
         --attribution-window-seconds ${attribution_windows[$i]} --per-user-credit-cap ${user_cappings[$j]} > $LOGFILE 2>&1
       done
    done
  done
done

cd -
