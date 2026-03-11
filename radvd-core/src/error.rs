use std::io;
use thiserror::Error;

pub type RadvdResult<T> = Result<T, RadvdError>;

#[derive(Error, Debug)]
pub enum RadvdError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Interface error: {0}")]
    Interface(String),

    #[error("Socket error: {0}")]
    Socket(String),

    #[error("Permission denied: {0}")]
    Permission(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("System error: {0}")]
    System(String),

    #[error("Other error: {0}")]
    Other(String),
}

impl RadvdError {
    pub fn config<S: Into<String>>(msg: S) -> Self {
        RadvdError::Config(msg.into())
    }

    pub fn parse<S: Into<String>>(msg: S) -> Self {
        RadvdError::Parse(msg.into())
    }

    pub fn network<S: Into<String>>(msg: S) -> Self {
        RadvdError::Network(msg.into())
    }

    pub fn interface<S: Into<String>>(msg: S) -> Self {
        RadvdError::Interface(msg.into())
    }

    pub fn socket<S: Into<String>>(msg: S) -> Self {
        RadvdError::Socket(msg.into())
    }
}
