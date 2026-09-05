#![deny(rust_2018_idioms)]
#![doc(
    html_logo_url = "https://storage.googleapis.com/fdo-gitlab-uploads/project/avatar/3213/zbus-logomark.png"
)]
#![doc = include_str!("../README.md")]

mod error;
pub use error::*;
pub mod identify;
pub mod polkitagent;

pub mod policykit1;
