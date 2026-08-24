//! Layer Minus overlay client.
//!
//! L0 protocol: exclusive `l0_listen` / `l0_connect` occupancy pipe on SI.
//! Application duplex (`duplex_offer` / `duplex_accept` / `duplex_frame`) rides
//! on that pipe after occupy. Do not claim SI `duplex_*`, `p2p_stream_*`, or
//! `listenKind: "l1p2p"`. A failed duplex line is closed and its bytes are
//! discarded; it never falls back to P1. HTTP first body is still
//! `{ "data": "<armor>" }`.

pub mod address_pgp;
pub mod aes;
pub mod client;
pub mod duplex;
pub mod eip191;
pub mod envelope;
pub mod frame;
pub mod identity;
pub mod listen;
pub mod pgp;
pub mod pipe;
pub mod post;
pub mod proxy;
pub mod si_pool;

pub use client::L0Client;
