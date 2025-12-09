pub mod manager;

pub async fn fetch(storage_url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let manager = manager::get_manager(storage_url).await?;
    let data = manager.fetch().await?;
    Ok(data)
}

pub async fn push(storage_url: &str, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let manager = manager::get_manager(storage_url).await?;
    manager.push(bytes).await?;
    Ok(())
}
