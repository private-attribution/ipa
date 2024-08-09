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
cp in-market-test/v2/ansible/inventory-template.ini in-market-test/v2/ansible/inventory.ini
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

### Upload network.toml

You'll now need to update the network.toml file and upload it.

```
cp in-market-test/v2/ansible/network-template.toml in-market-test/v2/ansible/network.toml
```

All three helpers need to have the same network.toml, in the same order. For each helper, you'll update:
1. Their `cert`, from their cert.pem
2. Their `url` (the hostname / ip address)
3. Their `public_key`, from mk.pub


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

### Kill helper

```
ansible-playbook -i in-market-test/v2/ansible/inventory.ini in-market-test/v2/ansible/kill_helper.yaml
```
