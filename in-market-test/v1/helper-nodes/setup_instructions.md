Here are the instructions for setting up node for running IPA.

## Step 1: Download code and run a sample test
1. If you do not have Rust installed on your machine, you can follow [these](https://doc.rust-lang.org/book/ch01-01-installation.html#installation) instructions to do so.
2. Download the code from https://github.com/private-attribution/ipa
   You can do this by running the command on the terminal:
   `git clone https://github.com/private-attribution/ipa`
3. This will create a folder named “ipa”. Go inside the folder.

   Command: `cd ipa`
4. Build the Rust code

   Command: `cargo build`
5. Running a sample test :

   Command: `cargo bench --bench oneshot_ipa --features="enable-benches" --no-default-features`

## Step 2: Setup helper configuration
1. Provide details of how the machine can be accessed from public internet. For this, we would need to know
   i.  IP address/DNS which is accessible from public internet (i.e. firewall allows connecting to the helper port (443))
   ii. Confirm if machine is able to listen on port 443

2. Installing/Upgrading Docker
   - If you need to install docker, follow the instructions [here](https://docs.docker.com/engine/install/).
   - If you already have docker, ensure that you are running at least Docker Version 20.10.22. You can check version by running command `docker -v` on the terminal.

3. Download docker image of IPA from shared folder. It will be uploaded in an executable docker image which will have IPA code.

   Link: TBD.

   Alternatively, you can build the docker image directly from the Rust code with this command

       `cd <path_to_ipa_source_code>`

       `scripts/helper-image.sh --identity 1 --hostname localhost`

3. Get your public and private keys

   Docker image already contains (default) public and private keys for encrypting match keys and also,
   to secure the report files while in transit.

   1. Check which docker images are available to run and their TAGs, run following command:

      `docker images`

      You should be able to see "private-attribution/ipa" in the list along with its TAG

   2. To run the docker container with a bash terminal and see what is inside the image run:

      `docker run -it docker.io/private-attribution/ipa:<IMAGE_TAG> /bin/bash`

   3. To copy a TLS public key and matchkey encryption public key from the docker image to the host :

      - Open a separate terminal and run following command to see available docker images

         - `docker container ls`

         - Copy the CONTAINER ID corresponding to your IMAGE.

        You will know what is your Helper party number i.e. 1,2 or 3. Here we show for Helper `1`:

        `docker cp <CONTAINER_ID>:/etc/ipa/pub/h1.pem .  `
        `docker cp <CONTAINER_ID>:/etc/ipa/pub/h1-mk.pub .  `

        To copy a TLS public key and matchkey encryption public key from Helper `2` from the host onto the docker image run from the directory with the public key `2.pem`:

        `docker cp h2.pem <IMAGE_ID>:/etc/ipa/pub/`
        `docker cp h2-mk.pub <IMAGE_ID>:/etc/ipa/pub/`



4. Upload the public TLS and matchkey encryption keys in a shared folder. Save the private TLS and decryption keys in a safe place.

5. Once all the helpers have uploaded their public keys in the shared folder, download it and run a script to generate network configuration.

   Command: TBD

6. Start the helper server using a provided command.

   Command: TBD

## Step 3: Run sample test across 3 helper parties
IPA team is still working on this and we will populate this section once the instructions are ready