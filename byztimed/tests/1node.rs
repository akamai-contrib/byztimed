//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

extern crate byztimed;
extern crate nix;
extern crate tempfile;

#[macro_use]
extern crate lazy_static;

use std::env;
use std::fs;
use std::io;
use std::path;
use std::process;
use std::thread;
use std::time;

use byztime::Context;

mod common;
use common::*;

const GORGIAS_CONFIG: &'static str = r#"{
    "timedata": "@tempdir@/gorgias.timedata",
    "secret_store": "@tempdir@/gorgias.store",
    "bind_port": @gorgias_port@,
    "key": "@certdir@/gorgias.key",
    "cert": "@certdir@/gorgias.crt",
    "authorities": "@certdir@/trent.crt",
    "logging": { "@tempdir@/gorgias.log": "debug" },
    "peers": {}
}"#;

///Greatest allowed (max - min) in any peer for a successful test, in nanoseconds
const SPAN_LIMIT: i64 = 25_000_000;

#[test]
fn one_node() {
    match std::env::var_os("BYZTIMED_SAVE_INTEGRATION_TEST_OUTPUT") {
        None => {
            let temp_dir = tempfile::tempdir().unwrap();
            run_one_node(temp_dir.path())
        }
        Some(dir) => run_one_node(dir.as_ref()),
    }
}

fn run_one_node(temp_dir: &path::Path) {
    let testbin_path = env::current_exe().unwrap();
    let testbin_dir = testbin_path.parent().unwrap();
    let bin_dir = testbin_dir.parent().unwrap();
    let mut byztime_bin_path = bin_dir.to_owned();
    byztime_bin_path.push("byztimed");
    byztime_bin_path.set_extension(env::consts::EXE_EXTENSION);
    assert!(byztime_bin_path.exists());

    /* Find the certificate directory */
    let mut cert_dir = path::PathBuf::new();
    cert_dir.push(env!("CARGO_MANIFEST_DIR"));
    cert_dir.push("tests");
    cert_dir.push("test_certs");
    assert!(cert_dir.exists());

    let our_port = find_ports(1);

    let config_contents = GORGIAS_CONFIG
        .replace("/", &path::MAIN_SEPARATOR.to_string())
        .replace("@gorgias_port@", &our_port[0].to_string())
        .replace("@tempdir@", temp_dir.to_str().unwrap())
        .replace("@certdir@", cert_dir.to_str().unwrap());

    //Write configuration file
    let mut config_path = path::PathBuf::new();
    config_path.push(temp_dir);
    config_path.push("gorgias.json");
    fs::write(&config_path, &config_contents).unwrap();

    //Remove any existing timedata file
    let mut timedata_path = path::PathBuf::new();
    timedata_path.push(temp_dir);
    timedata_path.push("gorgias.timedata");
    if let Err(e) = fs::remove_file(&timedata_path) {
        assert!(e.kind() == io::ErrorKind::NotFound);
    }

    //Create the store path
    let mut store_path = path::PathBuf::new();
    store_path.push(temp_dir);
    store_path.push("gorgias.store");
    fs::create_dir(&store_path).unwrap();

    //Capture stderr
    let mut stderr_path = path::PathBuf::new();
    stderr_path.push(temp_dir);
    stderr_path.push("gorgias.stderr");
    let stderr = fs::File::create(stderr_path).unwrap();

    let mut child: ChildWrapper = process::Command::new(&byztime_bin_path)
        .arg(&config_path)
        .stderr(stderr)
        .spawn()
        .unwrap()
        .into();

    thread::sleep(time::Duration::from_secs(2));

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();

    thread::sleep(time::Duration::from_secs(1));
    let _ = child.kill();

    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty());
    if !output.status.success() {
        panic!("Output status: {}", output.status)
    }

    let mut log_path = path::PathBuf::new();
    log_path.push(temp_dir);
    log_path.push("gorgias.log");
    let log_contents = String::from_utf8(fs::read(&log_path).unwrap()).unwrap();
    assert!(log_contents.find("ERROR").is_none());

    let ctx = byztime::ConsumerContext::open(timedata_path.as_ref()).unwrap();
    let (min, _, max) = ctx.offset().unwrap();
    ctx.close().unwrap();

    assert!(max - min < byztime::Timestamp::new(0, SPAN_LIMIT));
}
