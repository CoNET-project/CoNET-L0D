//! Layer Minus overlay client.
//!
//! Do not claim a live SI command named `p2p_stream_*` or `listenKind: "l1p2p"`.
//! Any byte-stream must reuse `POST /post` with `{ "data": "<armor>" }`.

pub mod address_pgp;
pub mod client;
pub mod envelope;
pub mod frame;
pub mod pgp;
pub mod post;

pub use client::L0Client;
