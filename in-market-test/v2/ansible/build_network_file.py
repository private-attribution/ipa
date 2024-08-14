import argparse
import configparser
import os
import re
import sys
from pathlib import Path


def get_urls_from_config():
    # Read the Ansible inventory file
    config = configparser.ConfigParser()
    config.read(Path("in-market-test/v2/ansible/inventory.ini"))

    hosts = [s.split(" ")[0] for s in list(config["myhosts"].keys())]

    if len(hosts) != 3:
        print(f"ERROR: Expected 3 hosts in inventory.ini, but found {len(hosts)}")
        sys.exit(1)

    ssh_config_path = os.path.expanduser("~/.ssh/config")
    # Read the SSH config file
    with open(ssh_config_path, "r") as f:
        ssh_config = f.read()
    # Parse the SSH config file to get the hostname for each host
    hostnames = {}
    hostname_match = re.findall(r"Host (\S+)\n[\s\t]+HostName (\S+)", ssh_config)
    hostnames = {host: hostname for (host, hostname) in hostname_match if host in hosts}

    missing_hosts = [host for host in hosts if hostnames.get(host) is None]
    if missing_hosts:
        print(
            f"ERROR: ~/.ssh/config is missing hostnames for host: {', '.join(missing_hosts)}"
        )
        sys.exit(1)

    return tuple(hostnames[host] for host in hosts)


def get_urls():
    parser = argparse.ArgumentParser(description="Tool to build network.toml from keys")
    parser.add_argument(
        "--config",
        action="store_true",
        help="Load urls from inventory.ini and ~/.ssh/config",
    )
    parser.add_argument(
        "--helper1-url",
        required=False,
        help="URL of helper1",
    )
    parser.add_argument(
        "--helper2-url",
        required=False,
        help="URL of helper2",
    )
    parser.add_argument(
        "--helper3-url",
        required=False,
        help="URL of helper3",
    )
    args = vars(parser.parse_args())

    if args["config"]:
        return get_urls_from_config()
    else:
        missing_args = [arg for (arg, url) in args.items() if url is None]
        if missing_args:
            print(
                "ERROR: If not loading from config, --helper1-url, --helper2-url, "
                "and, --helper3-url are all required."
            )
            sys.exit(1)
        return (args["helper1_url"], args["helper2_url"], args["helper3_url"])


def main():

    urls = get_urls()
    certs = (
        Path("in-market-test/v2/deployed_keys/1-cert.pem").read_text(),
        Path("in-market-test/v2/deployed_keys/2-cert.pem").read_text(),
        Path("in-market-test/v2/deployed_keys/3-cert.pem").read_text(),
    )
    public_keys = (
        Path("in-market-test/v2/deployed_keys/1-mk.pub").read_text(),
        Path("in-market-test/v2/deployed_keys/2-mk.pub").read_text(),
        Path("in-market-test/v2/deployed_keys/3-mk.pub").read_text(),
    )

    network_template = f"""
[[peers]]
certificate = \"\"\"
{certs[0]}\"\"\"
url = "{urls[0]}"

[peers.hpke]
public_key = "{public_keys[0]}"

[[peers]]
certificate = \"\"\"
{certs[1]}\"\"\"
url = "{urls[1]}"

[peers.hpke]
public_key = "{public_keys[1]}"

[[peers]]
certificate = \"\"\"
{certs[2]}\"\"\"
url = "{urls[2]}"

[peers.hpke]
public_key = "{public_keys[2]}"

[client.http_config]
ping_interval_secs = 90.0
version = "http2"
"""

    network_file = Path("in-market-test/v2/ansible/network.toml")

    network_file.write_text(network_template)


if __name__ == "__main__":
    main()
