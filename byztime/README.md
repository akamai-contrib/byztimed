Byztime is a Byzantine-fault-tolerant protocol for synchronizing
time among a group of peers, without reliance on any external
authority. This crate wraps
[byztime_sys](https://crates.io/crates/byztime-sys) (which in turn
wraps the C library
[libbyztime](https://github.com/akamai-contrib/libbyztime)) to
provide an idiomatic Rust API for communication from
[byztimed](https://crates.io/crates/byztimed) to applications which
consume time from it.