#!/bin/bash
# script to just run the DP module tests when developing
# run as: ./dp_tests.sh
set -e
cargo test --no-run
cargo test protocol::dp::distributions::tests::test_geometric_constructor
cargo test protocol::dp::distributions::tests::test_double_geometric_constructor
cargo test protocol::dp::distributions::tests::test_truncated_double_geometric_constructor
cargo test protocol::dp::distributions::tests::dp_normal_distribution_sample_random
cargo test protocol::dp::distributions::tests::dp_normal_distribution_sample_random
cargo test protocol::dp::distributions::tests::dp_normal_distribution_sample_standard
cargo test protocol::dp::distributions::tests::test_truncated_double_geometric
cargo test protocol::dp::distributions::tests::test_truncated_double_geometric_hoffding
cargo test protocol::dp::distributions::tests::dp_rounded_normal_distribution_sample_random
cargo test protocol::dp::distributions::tests::test_truncated_double_geometric
cargo test protocol::dp::insecure::test::dp_bad_delta
cargo test protocol::dp::insecure::test::dp_bad_epsilon
cargo test protocol::dp::insecure::test::dp_normal_distribution_apply
cargo test protocol::dp::insecure::test::dp_normal_distribution_generation_random
cargo test protocol::dp::insecure::test::dp_normal_distribution_generation_standard
cargo test protocol::context::tests::semi_honest_metrics
cargo test protocol::dp::distributions::tests::test_geometric_sample_dist
cargo test protocol::dp::insecure::test::epsilon_variance_table
cargo test protocol::dp::insecure::test::test_oprf_padding_dp
cargo test protocol::dp::distributions::tests::test_truncated_double_geometric_sample_dist
cargo test protocol::boolean::solved_bits::tests::malicious
cargo test protocol::dp::insecure::test::test_find_smallest_n
cargo test protocol::dp::insecure::test::test_pow_u32
cargo test protocol::dp::insecure::test::output_differentially_private
