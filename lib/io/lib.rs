//! The I/O manager's rules for file systems, with no hardware or object
//! behind them, so the host can test them. The kernel (`kernel/io`)
//! holds the queues and sends the requests.

#![cfg_attr(not(test), no_std)]

pub mod mount;
