//! Layer Minus overlay client.
//!
//! L0 protocol: exclusive `l0_listen` / `l0_connect` occupancy pipe on SI.
//! Application duplex (`duplex_offer` / `duplex_accept` / `duplex_frame`) rides
//! on that pipe after occupy. Do not claim SI `duplex_*`, `p2p_stream_*`, or
//! `listenKind: "l1p2p"`. Missing accept keeps P1 gossip. HTTP first body is
//! still `{ "data": "<armor>" }`.

pub mod address_pgp;
pub mod aes;
pub mod client;
pub mod duplex;
pub mod eip191;
pub mod envelope;
pub mod frame;
pub mod listen;
pub mod pgp;
pub mod pipe;
pub mod post;

pub use client::L0Client;
