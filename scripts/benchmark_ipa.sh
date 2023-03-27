#!/bin/bash

# Generate stage-wise report after running IPA bench
#
# To use, supply the number of rows you want to run benchmarking on

num_rows=$1
if [ "$#" -ne 1 ]; then
    echo "Please supply query size as an argument to the script"
    exit
fi

temp_file=".benchmark_result$num_rows.csv"
RUST_LOG=raw_ipa=DEBUG cargo bench --bench oneshot_ipa --features="enable-benches" --no-default-features -- -n $num_rows > $temp_file
 
until_now_records=0
until_now_bytes=0

echo "Step,Bytes sent,Records Sent"
step_mapping=( 
        "mod_conv_breakdown_key\|mod_conv_match_key:Verify"
        "apply_sort_permutation\|gen_sort_permutation_from_match_keys:Sort"
	"accumulate_credit\|compute_helper_bits:Attribution"
  	"user_capping:Capping"
        "check_times_credit\|compute_equality_checks:Aggregation"
)
        

for step in "${step_mapping[@]}" ; do
    key=${step%%:*}
    value=${step#*:}
    records_sent=`grep "$key" $temp_file | awk -F, '{sum+=$2;}END{print sum;}'`
    bytes_sent=`grep "$key" $temp_file | awk -F, '{sum+=$3;}END{print sum;}'`

    echo "$value,$bytes_sent,$records_sent"
    until_now_records=$(($until_now_records+$records_sent))
    until_now_bytes=$(($until_now_bytes+$bytes_sent))
done

total_bytes=`cat $temp_file | awk -F, '{sum+=$3;}END{print sum;}'`
total_records=`cat $temp_file | awk -F, '{sum+=$2}END{print sum;}'`
echo "Others,$(($total_bytes-$until_now_bytes)),$(($total_records-$until_now_records))"
echo "Total,$total_bytes,$total_records"

rm $temp_file


