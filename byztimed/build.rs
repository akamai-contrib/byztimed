//Copyright 2020, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

extern crate prost_build;

fn main() {
    let mut prost_build = prost_build::Config::new();
    prost_build.type_attribute(
        ".",
        "#[cfg_attr(test, derive(quickcheck_derive::Arbitrary))]",
    );
    prost_build
        .compile_protos(&["src/wire.proto"], &["src/"])
        .unwrap();
}
