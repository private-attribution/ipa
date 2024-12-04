import os
import subprocess
import argparse
import shutil

# The following format is what ipa-infra project expects.
# See:
# https://github.com/private-attribution/ipa-infra/blob/main/templates/service.yaml
# https://github.com/private-attribution/ipa-infra/blob/main/templates/helpers.yaml
DNS_FORMAT = "h{}-helper-shard-{}.h{}-helper-shard.default.svc.cluster.local"

def generate_keys(base_dir, shard_count):
    """
    Generate keys for MPC setup.

    Args:
        base_dir (str): Base directory for generated files.
        shard_count (int): Number of shards.
        helper_name_format (str): Format for helper names.
    """

    # Create the base directory if it doesn't exist
    os.makedirs(base_dir, exist_ok=True)

    # Create the directory structure for each helper
    for i in range(1, 4):  # 3 helpers: 1, 2, 3
        for j in range(shard_count):
            helper_name = DNS_FORMAT.format(i, j, i)

            dir_path = f"{base_dir}/helper{i}/shard{j}"

            os.makedirs(dir_path, exist_ok=True)

            print(f"Generating keys for {helper_name}...")

            # Run keygen for each helper BUT we only generate MK keys for the first shard and
            # copy them for the rest.
            # This code needs to remain in sync with its Rust counterpart in:
            # https://github.com/private-attribution/ipa/blob/d8b73fb2521c8f90a8fd9897d462a5a9816adeb7/ipa-core/src/cli/clientconf.rs#L149
            keygen_cmd = [
                "./target/release/helper",
                "keygen",
                "--name",
                helper_name,
                "--tls-cert",
                f"{dir_path}/{helper_name}.pem",
                "--tls-key",
                f"{dir_path}/{helper_name}.key",
            ]

            if j == 0:  # Only add mk-public-key and mk-private-key params for the first shard
                keygen_cmd.extend([
                    "--mk-public-key",
                    f"{dir_path}/{helper_name}_mk.pub",
                    "--mk-private-key",
                    f"{dir_path}/{helper_name}_mk.key",
                ])

            subprocess.run(keygen_cmd)

            # Copy mk public and private keys from the first shard to other shards
            if j != 0:
                src_dir = f"{base_dir}/helper{i}/shard0"
                dst_dir = dir_path
                src_mk_pub_key = f"{src_dir}/{DNS_FORMAT.format(i, 0, i)}_mk.pub"
                src_mk_priv_key = f"{src_dir}/{DNS_FORMAT.format(i, 0, i)}_mk.key"
                dst_mk_pub_key = f"{dst_dir}/{helper_name}_mk.pub"
                dst_mk_priv_key = f"{dst_dir}/{helper_name}_mk.key"

                shutil.copy(src_mk_pub_key, dst_mk_pub_key)
                shutil.copy(src_mk_priv_key, dst_mk_priv_key)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate keys for MPC setup")
    parser.add_argument("-b", "--base-dir", type=str, required=True, help="Base directory for generated files")
    parser.add_argument("-s", "--shard-count", type=int, required=True, help="Number of shards")
    args = parser.parse_args()
    generate_keys(args.base_dir, args.shard_count)
