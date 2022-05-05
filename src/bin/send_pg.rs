// TODO: remove this file, since it is a sandbox to show error
use raw_ipa::error::Error;
use tokio::try_join;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let thread1 = t1(); //.await.map_err(Error::from)?;
    let join = tokio::spawn(thread1);
    let res = try_join!(join)?;
    println!("{}", res.0?);
    Ok(())
}

async fn t1() -> Result<String, Error> {
    Ok(String::from("asdfasdf"))
}
