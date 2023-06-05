#!/usr/bin/env bash

set -eou pipefail
set -o xtrace

REV=$(git log -n 1 --format='format:%H' | cut -c1-10)
COPY_CONTAINER_NAME="copy_container"
cleanup() {
  if docker ps -aq --filter "name=$COPY_CONTAINER_NAME" | grep -q .; then
    docker rm $COPY_CONTAINER_NAME > /dev/null
  fi
}
trap cleanup EXIT

# need to be consistent with `helper-image.sh`.
image_tag() {
  local identity="$1"
  local tag="private-attribution/ipa:$REV-h$identity"
  echo "$tag"
}

cd "$(dirname "$0")" || exit 1

cleanup

# generate 3 images
IDENTITY=1
HOST_NAMES=""
for hostname in "${@}"; do
#  ./helper-image.sh --hostname $hostname --identity $IDENTITY
  IDENTITY=$(( IDENTITY + 1 ));
  HOST_NAMES+="$hostname "
done;

## Copy TLS and mk public keys
#copy_file() {
#  local name="$1"
#  local ext="$2"
#
#  for ((src=0; src<=2; src++)); do
#    for ((dst=src+1; dst<=src+2; dst++)); do
#      from=$((src + 1))
#      to=$((dst % 3 + 1))
#      file="$name$from$ext"
#      echo "copying $file from $from to $to"
#      docker run --rm "$(image_tag $from)" cat $file \
#        | docker run -i --name $COPY_CONTAINER_NAME "$(image_tag $to)" sh -c 'cat > '$file \
#        && docker commit $COPY_CONTAINER_NAME "$(image_tag $to)" > /dev/null \
#        && docker rm $COPY_CONTAINER_NAME > /dev/null || exit 1
#    done;
#  done;
#}

#copy_file "/etc/ipa/pub/h" ".pem"
#copy_file "/etc/ipa/pub/h" "_mk.pub"

## generate network.toml
#for ((i=1; i<=3; i++)); do
#  docker run -i --name $COPY_CONTAINER_NAME  "$(image_tag $i)" /usr/local/bin/ipa-helper confgen --keys-dir /etc/ipa/pub --hosts $HOST_NAMES --ports 443 443 443 \
#    && docker commit $COPY_CONTAINER_NAME "$(image_tag $i)" > /dev/null \
#    && docker rm $COPY_CONTAINER_NAME > /dev/null || exit 1
#done;

# make 3 tar files to upload them to the destinations
mkdir -p /var/tmp/ipa
for ((i=1; i<=3; i++)); do
  docker save -o /var/tmp/ipa/ipa-$i.tar "$(image_tag $i)"
  rsync -avhP /var/tmp/ipa/ipa-$i.tar ec2-user@IPA-$i:/home/ec2-user/
done;



