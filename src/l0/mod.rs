//! Layer Minus overlay client.
//!
//! Do not claim a live SI command named `p2p_stream_*` or `listenKind: "l1p2p"`.
//! Overlay duplex is an **application** protocol on existing Chat listen +
//! user-PGP gossip. SI does not implement `duplex_*`. Fallback is P1 gossip
//! if the peer app never sends `duplex_accept`. Any byte-stream still reuses
//! `POST /post` with `{ "data": "<armor>" }`.

pub mod address_pgp;
pub mod aes;
pub mod client;
pub mod duplex;
pub mod eip191;
pub mod envelope;
pub mod frame;
pub mod listen;
pub mod pgp;
pub mod post;

pub use client::L0Client;
