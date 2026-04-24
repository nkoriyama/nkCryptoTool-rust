use crate::error::Result;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt, BufReader};
use std::sync::Arc;

pub type ProgressCallback = Arc<dyn Fn(f64) + Send + Sync>;

pub struct PipelineManager {
    stages: Vec<Box<dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync>>,
    chunk_size: usize,
}

impl PipelineManager {
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            chunk_size: 64 * 1024,
        }
    }

    pub fn add_stage<F>(&mut self, stage: F) 
    where 
        F: Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync + 'static 
    {
        self.stages.push(Box::new(stage));
    }

    pub async fn run<F, Fut>(
        &self,
        input_path: &Path,
        mut output_file: File,
        read_offset: u64,
        read_size: u64,
        finalizer: F,
        progress_callback: Option<ProgressCallback>,
        total_input_size: u64,
    ) -> Result<()> 
    where
        F: FnOnce(&mut File) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let input_file = File::open(input_path).await?;
        let mut reader = BufReader::new(input_file);
        reader.seek(std::io::SeekFrom::Start(read_offset)).await?;

        let mut total_read = 0u64;
        let mut buffer = vec![0u8; self.chunk_size];

        while total_read < read_size {
            let to_read = std::cmp::min(self.chunk_size as u64, read_size - total_read) as usize;
            let n = reader.read(&mut buffer[..to_read]).await?;
            if n == 0 { break; }
            
            let mut data = buffer[..n].to_vec();
            for stage in &self.stages {
                data = stage(&data)?;
            }

            if !data.is_empty() {
                output_file.write_all(&data).await?;
                
                if let Some(ref cb) = progress_callback {
                    if total_input_size > 0 {
                        cb(total_read as f64 / total_input_size as f64);
                    }
                }
            }
            total_read += n as u64;
        }

        finalizer(&mut output_file).await?;
        output_file.flush().await?;

        Ok(())
    }
}
