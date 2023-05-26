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

2. Download docker image of IPA from shared folder. 
    
   We will be uploading an executable docker image which will have IPA code.
   
   Link: TBD

3. Docker image already contains (default) public and private keys for encrypting match keys and also, 
   to secure the report files while in transit.
  
   1. If you need to install docker, follow the instructions [here](https://docs.docker.com/engine/install/). 
   
   2.  To see what docker images are available run and what their TAGs and IDs are run:
   
       `docker images`

   3. To run the docker container with a bash terminal and see what is inside the image run: 
   
       `docker run -it docker.io/private-attribution/ipa:<IMAGE_TAG> /bin/bash`
   
   4. To copy a TLS public key from the docker image to the host run the following command in a terminal open in the host directory 
      to which you want to copy the key.  You will know what your Helper party number is yours `{1,2,3}`, here we show for Helper `1`: 
   
      `docker cp <IMAGE_ID>:/etc/ipa/pub/1.pem .  `
   5. To copy a TLS public key from Helper `2` from the host onto the docker image run from the directory with the public key `2.pem`: 
   
      `docker cp 2.pem <IMAGE_ID>:/etc/ipa/pub/`
   6. To copy a public key used to encrypt the matchkeys from the docker image to the host run:

      Command: TBD
   
   7. To copy a public key used to encrypt the matchkeys from the host to the docker image run:

      Command: TBD





4. Upload the public TLS and matchkey encryption keys in a shared folder. Save the private TLS and decryption keys in a safe place.

5. Once all the helpers have uploaded their public keys in the shared folder, download it and run a script to generate network configuration.
   
   Command: TBD

6. Start the helper server using a provided command.
   
   Command: TBD

## Step 3: Run sample test across 3 helper parties
   IPA team is still working on this and we will populate this section once the instructions are ready
