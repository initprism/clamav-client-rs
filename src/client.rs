use byteorder::{BigEndian, ByteOrder};
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::ClamError;
use crate::response::{ScanResult, Stats, Version};

pub type Result<T> = std::result::Result<T, ClamError>;

pub struct ClamClient {
    socket: SocketAddr,
    timeout: Option<Duration>,
}

impl ClamClient {
    fn build(h: &str, p: u16, timeout: Option<Duration>) -> Result<Self> {
        let address = format!("{}:{}", h, p);

        let socket = match address.to_socket_addrs() {
            Ok(mut iter) => match iter.next() {
                Some(socket) => socket,
                None => {
                    return Err(ClamError::InvalidData(String::from(
                        "invalid socket address",
                    )))
                }
            },
            Err(e) => return Err(ClamError::InvalidIpAddress(e)),
        };

        Ok(Self { socket, timeout })
    }

    pub fn new(h: &str, p: u16) -> Result<Self> {
        Self::build(h, p, None)
    }

    pub fn new_with_timeout(h: &str, p: u16, t: u64) -> Result<Self> {
        Self::build(h, p, Some(Duration::from_secs(t)))
    }

    pub fn ping(&self) -> bool {
        match self.command(b"zPING\0") {
            Ok(resp) => resp == "PONG",
            Err(_) => false,
        }
    }

    pub fn version(&self) -> Result<Version> {
        let resp = self.command(b"zVERSION\0")?;
        Version::parse(&resp)
    }

    pub fn reload(&self) -> Result<String> {
        self.command(b"zRELOAD\0")
    }

    pub fn scan_path(&self, path: &str, continue_on_virus: bool) -> Result<Vec<ScanResult>> {
        let result = if continue_on_virus {
            self.command(&format!("zCONTSCAN {}\0", path).into_bytes())?
        } else {
            self.command(&format!("zSCAN {}\0", path).into_bytes())?
        };

        Ok(ScanResult::parse(result))
    }

    pub fn multiscan_path(&self, path: &str) -> Result<Vec<ScanResult>> {
        let result = self.command(&format!("zSCAN {}\0", path).into_bytes())?;
        Ok(ScanResult::parse(result))
    }

    pub fn scan_stream<T: Read>(&self, s: T) -> Result<ScanResult> {
        let mut reader = BufReader::new(s);
        let mut buffer = [0; 4096];
        let mut length_buffer = [0; 4];
        let mut connection = self.connect()?;

        self.connection_write(&connection, b"zINSTREAM\0")?;

        while let Ok(bytes_read) = reader.read(&mut buffer) {
            if bytes_read > std::u32::MAX as usize {
                return Err(ClamError::InvalidDataLength(bytes_read));
            }

            BigEndian::write_u32(&mut length_buffer, bytes_read as u32);

            self.connection_write(&connection, &length_buffer)?;
            self.connection_write(&connection, &buffer)?;

            if bytes_read < 4096 {
                break;
            }
        }

        self.connection_write(&connection, &[0, 0, 0, 0])?;

        let mut result = String::new();
        match connection.read_to_string(&mut result) {
            Ok(_) => {
                let scan_result = ScanResult::parse(&result);

                if let Some(singular) = scan_result.first() {
                    Ok(singular.clone())
                } else {
                    Err(ClamError::InvalidData(result))
                }
            }
            Err(e) => Err(ClamError::ConnectionError(e)),
        }
    }

    pub fn scan_string(&self, str: &str) -> Result<ScanResult> {
        self.scan_bytes(str.as_bytes().to_vec())
    }

    pub fn scan_bytes(&self, b: Vec<u8>) -> Result<ScanResult> {
        let mut connection = self.connect()?;
        self.connection_write(&connection, b"zINSTREAM\0")?;

        let buffer = b.chunks(4096);
        for chunks in buffer {
            let len = chunks.len();
            self.connection_write(&connection, &(len as u32).to_be_bytes())?;
            self.connection_write(&connection, chunks)?;
        }
        self.connection_write(&connection, &[0; 4])?;

        let mut result = String::new();
        match connection.read_to_string(&mut result) {
            Ok(_) => {
                let scan_result = ScanResult::parse(&result);

                if let Some(singular) = scan_result.first() {
                    Ok(singular.clone())
                } else {
                    Err(ClamError::InvalidData(result))
                }
            }
            Err(e) => Err(ClamError::ConnectionError(e)),
        }
    }

    pub fn scan_chunks(&self, chunks: std::slice::Chunks<u8>) -> Result<ScanResult> {
        let mut connection = self.connect()?;
        self.connection_write(&connection, b"zINSTREAM\0")?;

        for chunk in chunks {
            let len = chunk.len();
            self.connection_write(&connection, &(len as u32).to_be_bytes())?;
            self.connection_write(&connection, chunk)?;
        }
        self.connection_write(&connection, &[0; 4])?;

        let mut result = String::new();
        match connection.read_to_string(&mut result) {
            Ok(_) => {
                let scan_result = ScanResult::parse(&result);

                if let Some(singular) = scan_result.first() {
                    Ok(singular.clone())
                } else {
                    Err(ClamError::InvalidData(result))
                }
            }
            Err(e) => Err(ClamError::ConnectionError(e)),
        }
    }

    pub fn stats(&self) -> Result<Stats> {
        let resp: String = self.command(b"zSTATS\0")?;
        Stats::parse(&resp)
    }

    pub fn shutdown(self) -> Result<String> {
        self.command(b"zSHUTDOWN\0")
    }

    fn command(&self, c: &[u8]) -> Result<String> {
        let mut s = self.connect()?;

        match s.write_all(c) {
            Ok(_) => {
                let mut r = String::new();
                match s.read_to_string(&mut r) {
                    Ok(_) => Ok(r),
                    Err(e) => Err(ClamError::CommandError(e)),
                }
            }
            Err(e) => Err(ClamError::CommandError(e)),
        }
    }

    fn connection_write(&self, mut c: &TcpStream, d: &[u8]) -> Result<usize> {
        match c.write(d) {
            Ok(a) => Ok(a),
            Err(e) => Err(ClamError::CommandError(e)),
        }
    }

    fn connect(&self) -> Result<TcpStream> {
        let ea = match self.timeout {
            Some(t) => TcpStream::connect_timeout(&self.socket, t),
            None => TcpStream::connect(&self.socket),
        };

        match ea {
            Ok(s) => Ok(s),
            Err(e) => Err(ClamError::ConnectionError(e)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_client_no_timeout() {
        let cclient = ClamClient::new("127.0.0.1", 3310).unwrap();
        let socket_addr =
            ::std::net::SocketAddr::new(::std::net::IpAddr::from([127, 0, 0, 1]), 3310);
        assert_eq!(cclient.socket, socket_addr);
        assert_eq!(cclient.timeout, None);
    }

    #[test]
    fn test_client_with_timeout() {
        let cclient = ClamClient::new_with_timeout("127.0.0.1", 3310, 60).unwrap();
        let socket_addr =
            ::std::net::SocketAddr::new(::std::net::IpAddr::from([127, 0, 0, 1]), 3310);
        assert_eq!(cclient.socket, socket_addr);
        assert_eq!(cclient.timeout, Some(::std::time::Duration::from_secs(60)));
    }
}
