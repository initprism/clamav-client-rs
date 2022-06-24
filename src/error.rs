use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClamError {
    #[error("{0}")]
    InvalidIpAddress(std::io::Error),

    #[error("{0}")]
    ConnectionError(std::io::Error),

    #[error("{0}")]
    CommandError(std::io::Error),

    #[error("Could not parse: {0}")]
    InvalidData(::std::string::String),

    #[error("Invalid data length sent: {0}")]
    InvalidDataLength(usize),

    #[error("{0}")]
    DateParseError(chrono::format::ParseError),

    #[error("{0}")]
    IntParseError(std::num::ParseIntError),
}
