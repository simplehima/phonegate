use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let bind = std::env::var("PG_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let cfg = phonegate_relay::Config::from_env();
    let listener = TcpListener::bind(&bind).await?;
    tracing::info!(%bind, trust_proxy = cfg.trust_proxy, "phonegate relay listening");
    phonegate_relay::serve(listener, cfg).await
}
