Byztime is a Byzantine-fault-tolerant protocol for synchronizing
time among a group of peers, without reliance on any external
authority. This crate provides raw bindings to the C library
[libbyztime](https://github.com/akamai-contrib/libbyztime) which
handles communication between
[byztimed](https://crates.io/crates/byztimed) and applications which
consume time from it.