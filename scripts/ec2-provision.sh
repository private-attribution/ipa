#!/usr/bin/env bash
#
# Provision a single AWS EC2 instance.
#
# This script creates a new EC2 instance that runs Amazon Linux 2 and deploys
# IPA code there. It also makes it a Rust-dev environment, so cargo, rust and
# other tools are available there.
#
# Instance is configured with cloud-init file 'instance-config.yaml`.
#
# This requires AWS CLI to be installed on this machine
# https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
# and an active AWS account with credentials configured for it to use
# https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
#
# ## SSH access
# To be able to connect to the newly created instance, a key pair must exist and the public key must be present on the
# instance and registered inside `.ssh/authorized_keys` file. If `--key-name` argument is provided, it will be used to
# provide ssh access, otherwise this script will generate a fresh key pair and upload the newly created public key to
# the provisioned instance.

set -e

help() {
  echo "Usage: $0 --name <instance_name> [--region <region>] [--instance-type <instance_type>] [--key-name <key_name>]"
}

# Can't really use getopts because of Mac users :(
parse_args() {
  while [ "${1:-}" != "" ]; do
    case "$1" in
      --region)
        shift
        AWS_REGION="$1"
        ;;
      --name)
        shift
        INSTANCE_NAME="$1"
        ;;
      --instance-type)
        shift
        INSTANCE_TYPE="$1"
        ;;
      --key-name)
        shift
        KEY_NAME="$1"
        ;;
      *)
      # unknown option
      help
      exit 1
    esac
    shift
  done
}

AWS_REGION="us-west-2"
INSTANCE_TYPE="c6id.8xlarge" # 32 cores, 64 Gb memory, EBS storage.
SSH_CONFIG_FILE="$HOME/.ssh/config"
CLOUD_INIT_FILE="ec2-instance-config.yaml"

parse_args "$@"

# Check that required arguments were provided
if [[ -z "${AWS_REGION}" || -z "${INSTANCE_TYPE}" || -z "${INSTANCE_NAME}" ]]; then
    help
    exit 1
fi

echo "Checking prerequisites..."
if ! hash aws; then
  echo "AWS CLI is not installed"
  exit 1
fi

cd "$(dirname "$0")"

if [[ ! -f "$CLOUD_INIT_FILE" ]]; then
  echo "Cloud-init config file $CLOUD_INIT_FILE is missing."
  exit 1
fi

# Generate a new key pair if key name is not provided
if [[ -z "${KEY_NAME}" ]]; then
  # taking 30 symbols to get some redundancy because tr filters out some valid base64 symbols (=,/)
  RANDOM_STRING=$(head -c30 < /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | fold -w6 | head -n1)
  KEY_NAME="$INSTANCE_NAME-key-pair-$RANDOM_STRING"
  CERT_FILE="$HOME/.ssh/$KEY_NAME.pem"
  echo "Generating new key ${KEY_NAME}"
  aws ec2 create-key-pair --key-name "$KEY_NAME" --region $AWS_REGION --query 'KeyMaterial' --output text > "$CERT_FILE"
  chmod 400 "$CERT_FILE"
else
  # Check if the key pair file exists
  CERT_FILE="$HOME/.ssh/$KEY_NAME.pem"
  if [ ! -f "$CERT_FILE" ]; then
    echo "The specified key pair file $CERT_FILE does not exist"
    exit 1
  fi
  echo "Using the existing certificate: $CERT_FILE"
fi


echo "Provisioning 1 $INSTANCE_TYPE instance in $AWS_REGION"
INSTANCE_ID=$(aws ec2 run-instances \
  --count 1 \
  --image-id resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2 \
  --instance-type $INSTANCE_TYPE \
  --key-name "$KEY_NAME" \
  --region $AWS_REGION \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":200,"VolumeType":"gp3","Iops":10000}}]' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME}]" \
  --query 'Instances[0].InstanceId' \
  --user-data file://$CLOUD_INIT_FILE \
  --output text
)
PUBLIC_DNS=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region $AWS_REGION \
  --query 'Reservations[0].Instances[0].PublicDnsName' \
  --output text
)
echo "Instance $INSTANCE_ID is created and available by $PUBLIC_DNS path. Waiting for provisioning to complete..."

# Poll AWS until instance is in the running state
while true; do
  INSTANCE_STATE=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region $AWS_REGION \
    --query 'Reservations[0].Instances[0].State.Name' \
    --output text
  )
  if [ "$INSTANCE_STATE" == "running" ]; then
    echo "Instance $INSTANCE_ID is running"
    break
  fi
  echo "Instance $INSTANCE_ID is $INSTANCE_STATE, waiting for it to be running"
  sleep 5
done


echo "Adding $INSTANCE_NAME entry to SSH config file"
# Update SSH config file to add an entry to connect to the newly provisioned instance via its public IP
{
echo "Host $INSTANCE_NAME"
echo "    Hostname $PUBLIC_DNS"
echo "    User ec2-user"
echo "    IdentityFile $CERT_FILE"
} >> "$SSH_CONFIG_FILE"

echo "Successfully created EC2 instance $INSTANCE_ID"

