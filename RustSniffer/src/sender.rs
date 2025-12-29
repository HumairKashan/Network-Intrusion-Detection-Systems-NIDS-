use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use serde::Serialize;

pub struct SocketSender {
    stream: TcpStream,
}

impl SocketSender {
    pub async fn new(addr: &str) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self { stream })
    }

    pub async fn send_packet<T: Serialize>(&mut self, pkt: &T) -> anyhow::Result<()> {
        let json = serde_json::to_string(pkt)?;
        self.stream.write_all(json.as_bytes()).await?;
        self.stream.write_all(b"\n").await?;
        Ok(())
    }
}
