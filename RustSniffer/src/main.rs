mod capture;
mod features;
mod sender;
mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("[INFO] RustSniffer starting...");
    capture::start_capture().await?;
    Ok(())
}
