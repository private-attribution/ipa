import os
import subprocess
import argparse
import shutil

def generate_keys(base_dir, shard_count, helper_name_format):
    # Create the base directory if it doesn't exist
    os.makedirs(base_dir, exist_ok=True)
    # Create the directory structure for each helper
    for i in range(1, 4):  # Assuming 3 helpers
        for j in range(shard_count):
            helper_name = helper_name_format.format(i, j)
            dir_path = f"{base_dir}/helper{i}/shard{j}"
            os.makedirs(dir_path, exist_ok=True)
            # Run keygen for each helper
            keygen_cmd = [
                "./target/debug/helper",
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
                src_dir = f"{base_dir}/helper{i}/shard{0}"
                dst_dir = dir_path
                src_mk_pub_key = f"{src_dir}/{helper_name_format.format(i, 0)}_mk.pub"
                src_mk_priv_key = f"{src_dir}/{helper_name_format.format(i, 0)}_mk.key"
                dst_mk_pub_key = f"{dst_dir}/{helper_name}_mk.pub"
                dst_mk_priv_key = f"{dst_dir}/{helper_name}_mk.key"
                shutil.copy(src_mk_pub_key, dst_mk_pub_key)
                shutil.copy(src_mk_priv_key, dst_mk_priv_key)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate keys for MPC setup")
    parser.add_argument("-b", "--base-dir", type=str, required=True, help="Base directory for generated files")
    parser.add_argument("-s", "--shard-count", type=int, required=True, help="Number of shards")
    parser.add_argument("-f", "--helper-name-format", type=str, default="helper{}.shard{}.prod.ipa-helper.dev", help="Format for helper names")
    args = parser.parse_args()
    generate_keys(args.base_dir, args.shard_count, args.helper_name_format)