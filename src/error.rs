use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Error creating file: {0}")]
    FileCreation(String),

    #[error("Error reading file: {0}")]
    FileRead(String),

    #[error("Error writing to file: {0}")]
    FileWrite(String),

    #[error("Failed to initialize key generation context")]
    KeyGenerationInit,

    #[error("Failed to generate key pair: {0}")]
    KeyGeneration(String),

    #[error("Failed to set parameters: {0}")]
    Parameter(String),

    #[error("Failed to write private key to file: {0}")]
    PrivateKeyWrite(String),

    #[error("Failed to write public key to file: {0}")]
    PublicKeyWrite(String),

    #[error("Failed to load private key: {0}")]
    PrivateKeyLoad(String),

    #[error("Failed to load public key: {0}")]
    PublicKeyLoad(String),

    #[error("Signature verification failed")]
    SignatureVerification,

    #[error("An OpenSSL error occurred: {0}")]
    OpenSSL(String),

    #[error("A TPM error occurred: {0}")]
    TPM(String),

    #[error("Failed to load TPM provider")]
    TPMProviderLoad,

    #[error("No key protection provider is available")]
    ProviderNotAvailable,

    #[error("A key protection error occurred: {0}")]
    KeyProtection(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unknown error")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, CryptoError>;
