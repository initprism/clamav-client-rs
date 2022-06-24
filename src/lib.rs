#[macro_use]
extern crate serde;
#[macro_use]
extern crate nom;

pub use client::ClamClient;
pub use response::Signature;

pub mod client;
pub mod error;
pub mod response;
