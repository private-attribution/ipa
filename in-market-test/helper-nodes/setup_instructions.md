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
   i. IP address/DNS which is accessible from public internet (i.e. firewall allows connecting to the helper port (443))
   ii. Confirm if machine is able to listen on port 443 

2. Download docker image of IPA from shared folder. 
    
   We will be uploading an executable docker image which will have IPA code.
   
   Link: TBD

3. Generate public and private keys for encrypting match keys and also, to secure the report files while in transit.
   
   Command: 
   
   `mkdir ~/Keys && cargo run --bin=helper --no-default-features --features "web-app real-world-infra" keygen --name "test" --tls-cert ~/Keys/TLSCert --tls-key ~/Keys/TLSKey --matchkey-enc ~/Keys/MatchKeyEncryptionKey --matchkey-dec ~/Keys/MatchKeyDecryptionKey`

4. Upload the public TLS and matchkey encryption keys in a shared folder. Save the private TLS and decryption keys in a safe place.

5. Once all the helpers have uploaded their public keys in the shared folder, download it and run a script to generate network configuration.
   
   Command: TBD

6. Start the helper server using a provided command.
   
   Command: TBD

## Step 3: Run sample test across 3 helper parties
   IPA team is still working on this and we will populate this section once the instructions are ready
