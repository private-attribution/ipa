#!/usr/bin/env bash

# Generate stage-wise report after running IPA bench
#
# To use, supply the number of rows you want to run benchmarking on

num_rows=$1
if [ "$#" -ne 1 ]; then
    echo "Please supply query size as an argument to the script"
    exit
fi

echo "Step,Records,Bytes"

DISPLAY_STAGE=("Verify" "Sort" "Attribution" "Capping" "Aggregation" "Others")

records=
bytes=

for i in "${DISPLAY_STAGE[@]}"; do 
  records+=(0); 
  bytes+=(0);
done

while IFS=, read -d ' ' actual_step_name a b c d; do
    if [[ $actual_step_name != *"protocol"* ]]; then 
      continue
    fi

    # In case you add a new stage to DISPLAY_STAGE, please add corresponding step 
    # in below case to match expected DISPLAY_STAGE array index
    case "$actual_step_name" in
      */mod_conv_breakdown_key/*|*/mod_conv_match_key/*) step=0 ;;
      */apply_sort_permutation/*|*/gen_sort_permutation_from_match_keys/*) step=1 ;;
      */accumulate_credit/*|*/compute_helper_bits/*) step=2 ;;
      */user_capping/*) step=3 ;;
      */check_times_credit/*|*/compute_equality_checks/*) step=4 ;;
      *) step=5 ;;
    esac
    records[$step]=$((${records[$step]} + $a))
    bytes[$step]=$((${bytes[$step]} + $b))
done <<< $(RUST_LOG=ipa=DEBUG cargo bench --bench oneshot_ipa --features="enable-benches" --no-default-features -- -n $num_rows 2> /dev/null)

for step in "${!DISPLAY_STAGE[@]}"; do 
    echo "${DISPLAY_STAGE[$step]},${records[$step]},${bytes[$step]}"
done

