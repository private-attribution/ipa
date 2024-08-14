import configparser
import os
import re
from pathlib import Path


def get_hostnames():
    # Read the Ansible inventory file
    config = configparser.ConfigParser()
    config.read(Path("in-market-test/v2/ansible/inventory.ini"))

    hosts = [s.split(" ")[0] for s in list(config["myhosts"].keys())]

    ssh_config_path = os.path.expanduser("~/.ssh/config")
    # Read the SSH config file
    with open(ssh_config_path, "r") as f:
        ssh_config = f.read()
    # Parse the SSH config file to get the hostname for each host
    hostnames = {}
    hostname_match = re.findall(r"Host (\S+)\n[\s\t]+HostName (\S+)", ssh_config)
    hostnames = {host: hostname for (host, hostname) in hostname_match if host in hosts}

    return tuple(hostnames[host] for host in hosts)


def main():
    urls = get_hostnames()
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
