# In-Market Test (2024) - Helper Party Runbook

The runbook is set up to use [ansible](https://docs.ansible.com/ansible/latest/) to provision the remote machine. You can, of course, decide to run the commands in the ansible scripts manually if you prefer.

## Local Install

First, install [pipx](https://github.com/pypa/pipx?tab=readme-ov-file#install-pipx). On a Mac

```
brew install pipx
```

Then install ansible

```
pipx install --include-deps ansible
```


## Provisioning


### Launching
You'll need to provision a host on your cloud provider with roughly the following specs:
1. 32 vCPU
2. 64 GB memory
3. 12.5 Gbps network bandwidth

On AWS, we use c6id.8xlarge with the Amazon Linux 2023 AMI.

The host needs SSH access (from you, if you want to limit the IP range), and HTTPS access from the internet (e.g., port 443 needs to be open.) No other ports need to be opened.


### SSH access

You'll need to configure the ansible inventory and your ssh config. Save the SSH key provided by the cloud provider to your ssh directory, e.g. `~/.ssh/helper_connect.pem`, then update `~/.ssh/config` to include:

```
Host ipa-helper
  HostName <ipa-helper-ip-or-public-dns-name>
  User <associated-user>
  IdentityFile ~/.ssh/helper_connect.pem
```

Now, copy the inventory template

```
cp in-market-test/v2/ansible/templates/inventory-template.ini in-market-test/v2/ansible/inventory.ini
```
and update it with the host name used in the SSH config and the assigned identity (1,2, or 3):

```
[myhosts]
ipa-helper           identity=1

[myhosts:vars]
ansible_python_interpreter=/usr/bin/python3
```

### Install dependencies and compile IPA

This command installs dependencies and compiles IPA. Note: it uses `yum`. If you need to use a different package manager, you can update the file.
```
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/provision.yaml
```

### Generate Keys

```
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/gen_keys.yaml
```
This should download `cert.pem` and `mk.pub` locally.

Warning: After sharing the public keys with other helpers (in the next step), you'll want to avoid rerunning this command. However, they are generated in the form of `<timestamp>-cert.pem` and `<timestamp>-mk.pub`, to prevent overwrite if you happen to run this command again. On the machine, it makes a copy of these timestamps into a fixed location (`in-market-test/v2/deployed_keys/cert.pem`, ...), which are used below to start the helper. If they are accidentally overwritten, you'll need to manually copy the correct ones into the expected location.


### Share public information with other helpers

All helpers will need to share with other helpers:
1. Their hostname/ip address (used in the .ssh/config, and in the key-gen)
2. Their cert.pem
3. Their mk.pub

These are all public keys, and are only used for encryption, not decryption.

Helpers must also agree on identities (1, 2, or 3). The order does not have impact on the process.

After adding these to `in-market-test/v2/deployed_keys`, it should contain:
- 1-cert.pem
- 1-mk.pub
- 2-cert.pem
- 2-mk.pub
- 3-cert.pem
- 3-mk.pub

With all of these, and the url for each helper, you can then generate the `network.toml` file:

```
python3 in-market-test/v2/ansible/build_network_file.py --helper1-url <helper1_url> --helper2-url <helper2_url> --helper3-url <helper3_url>
```

If running a test with 3 servers, this can also load these automatically from `~/.ssh/config` and `inventory.ini` with:
```
python3 in-market-test/v2/ansible/build_network_file.py --config
```


### Upload network.toml

```
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/upload_network_toml.yaml
```

## Start helper

```
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/start_helper.yaml
```

### See logs

```
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/print_helper_logs.yaml
```
There is also a script to parse the logs and get a run time report:
```
python3 in-market-test/v2/ansible/parse_logs.py
```


### Kill helper

```
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/kill_helper.yaml
```


## Run a test query

### Start 3 helper servers
If you spin up 3 servers, and put all 3 of them in your `~/.ssh/config` and `inventory.ini`, you should be able to get them all running with just the provided commands, e.g.:

```
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/kill_helper.yaml
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/provision.yaml
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/gen_keys.yaml
python3 in-market-test/v2/ansible/build_network_file.py --config
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/upload_network_toml.yaml
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/start_helper.yaml
```

### Run a test query
You can do this portion locally or from a 4th server, so long as you have access to port 433 on all 3 servers.

First, build the report collector binary:

```
cargo build --bin report_collector --features="cli test-fixture web-app"
```

Generate input data:
```
./target/debug/report_collector gen-ipa-inputs -n 10000 > input-data-10000.txt
```

Run a test query:
```
./target/debug/report_collector --network in-market-test/v2/ansible/network.toml --input-file input-data-10000.txt oprf-ipa --max-breakdown-key 64 --per-user-credit-cap 64 --plaintext-match-keys
```
