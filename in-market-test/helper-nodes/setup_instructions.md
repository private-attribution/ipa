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
   
## Step 2: Run sample test across 3 local nodes
   IPA team is still working on this and we will populate this section once the instructions are ready
   
## Step 3: Run sample test across 3 helper parties
   IPA team is still working on this and we will populate this section once the instructions are ready
