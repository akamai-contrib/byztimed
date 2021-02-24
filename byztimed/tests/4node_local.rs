//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

extern crate byztimed;
extern crate nix;
extern crate tempfile;

#[macro_use]
extern crate lazy_static;

use byztime::Context;
use std::env;
use std::fs;
use std::io;
use std::io::Write;
use std::path;
use std::process;
use std::thread;
use std::time;

mod common;
use common::*;

const ALICE_CONFIG: &'static str = r#"{
    "timedata": "@tempdir@/alice.timedata",
    "secret_store": "@tempdir@/alice.store",
    "bind_port": @alice_port@,
    "key": "@certdir@/alice.key",
    "cert": "@certdir@/alice.crt",
    "authorities": "@certdir@/trent.crt",
    "logging": { "@tempdir@/alice.log": "debug" },
    "poll_interval": 0.5,
    "peers": {
        "bob": {
            "host": "127.0.0.1",
            "port": @bob_port@,
            "cert_name": "bob.test"
        },
        "charlie": {
            "host": "127.0.0.1",
            "port": @charlie_port@,
            "cert_name": "charlie.test"
        },
        "dave": {
            "host": "127.0.0.1",
            "port": @dave_port@,
            "cert_name": "dave.test"
        }
    }
}"#;

const BOB_CONFIG: &'static str = r#"{
    "timedata": "@tempdir@/bob.timedata",
    "secret_store": "@tempdir@/bob.store",
    "bind_port": @bob_port@,
    "key": "@certdir@/bob.key",
    "cert": "@certdir@/bob.crt",
    "authorities": "@certdir@/trent.crt",
    "logging": { "@tempdir@/bob.log": "debug" },
    "poll_interval": 0.5,
    "peers": {
        "alice": {
            "host": "127.0.0.1",
            "port": @alice_port@,
            "cert_name": "alice.test"
        },
        "charlie": {
            "host": "127.0.0.1",
            "port": @charlie_port@,
            "cert_name": "charlie.test"
        },
        "dave": {
            "host": "127.0.0.1",
            "port": @dave_port@,
            "cert_name": "dave.test"
        }
    }
}"#;

const CHARLIE_CONFIG: &'static str = r#"{
    "timedata": "@tempdir@/charlie.timedata",
    "secret_store": "@tempdir@/charlie.store",
    "bind_port": @charlie_port@,
    "key": "@certdir@/charlie.key",
    "cert": "@certdir@/charlie.crt",
    "authorities": "@certdir@/trent.crt",
    "logging": { "@tempdir@/charlie.log": "debug" },
    "poll_interval": 0.5,
    "peers": {
        "alice": {
            "host": "127.0.0.1",
            "port": @alice_port@,
            "cert_name": "alice.test"
        },
        "bob": {
            "host": "127.0.0.1",
            "port": @bob_port@,
            "cert_name": "bob.test"
        },
        "dave": {
            "host": "127.0.0.1",
            "port": @dave_port@,
            "cert_name": "dave.test"
        }
    }
}"#;

const DAVE_CONFIG: &'static str = r#"{
    "timedata": "@tempdir@/dave.timedata",
    "secret_store": "@tempdir@/dave.store",
    "bind_port": @dave_port@,
    "key": "@certdir@/dave.key",
    "cert": "@certdir@/dave.crt",
    "authorities": "@certdir@/trent.crt",
    "logging": { "@tempdir@/dave.log": "debug" },
    "poll_interval": 0.25,
    "peers": {
        "alice": {
            "host": "127.0.0.1",
            "port": @alice_port@,
            "cert_name": "alice.test"
        },
        "bob": {
            "host": "127.0.0.1",
            "port": @bob_port@,
            "cert_name": "bob.test"
        },
        "charlie": {
            "host": "127.0.0.1",
            "port": @charlie_port@,
            "cert_name": "charlie.test"
        }
    }
}"#;

///Greatest allowed (max - min) in any peer for a successful test, in nanoseconds
const SPAN_LIMIT: i64 = 25_000_000;

///Greatest allowed range in estimates for a successful test, in nanoseconds
const DISPERSION_LIMIT: i64 = 1_000_000;

#[test]
fn four_node_local() {
    match std::env::var_os("BYZTIMED_SAVE_INTEGRATION_TEST_OUTPUT") {
        None => {
            let temp_dir = tempfile::tempdir().unwrap();
            run_four_node_local(temp_dir.path())
        }
        Some(dir) => run_four_node_local(dir.as_ref()),
    }
}

fn run_four_node_local(temp_dir: &path::Path) {
    /* Find the byztimed binary */
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

    let mut children = Vec::<ChildWrapper>::new();

    let our_ports = find_ports(4);

    for (config_filename, timedata_filename, store_dirname, stderr_filename, config_template) in &[
        (
            "alice.json",
            "alice.timedata",
            "alice.store",
            "alice.stderr",
            ALICE_CONFIG,
        ),
        (
            "bob.json",
            "bob.timedata",
            "bob.store",
            "bob.stderr",
            BOB_CONFIG,
        ),
        (
            "charlie.json",
            "charlie.timedata",
            "charlie.store",
            "charlie.stderr",
            CHARLIE_CONFIG,
        ),
        (
            "dave.json",
            "dave.timedata",
            "dave.store",
            "dave.stderr",
            DAVE_CONFIG,
        ),
    ] {
        //Generate configuration file
        let config_contents = config_template
            .replace("/", &path::MAIN_SEPARATOR.to_string())
            .replace("@alice_port@", &our_ports[0].to_string())
            .replace("@bob_port@", &our_ports[1].to_string())
            .replace("@charlie_port@", &our_ports[2].to_string())
            .replace("@dave_port@", &our_ports[3].to_string())
            .replace("@tempdir@", temp_dir.to_str().unwrap())
            .replace("@certdir@", cert_dir.to_str().unwrap());

        //Write configuration file
        let mut config_path = path::PathBuf::new();
        config_path.push(temp_dir);
        config_path.push(config_filename);
        fs::write(&config_path, &config_contents).unwrap();

        //Remove any existing timedata file
        let mut timedata_path = path::PathBuf::new();
        timedata_path.push(temp_dir);
        timedata_path.push(timedata_filename);
        if let Err(e) = fs::remove_file(&timedata_path) {
            assert!(e.kind() == io::ErrorKind::NotFound);
        }

        //Create the store path
        let mut store_path = path::PathBuf::new();
        store_path.push(temp_dir);
        store_path.push(store_dirname);
        fs::create_dir(&store_path).unwrap();

        //Capture stderr
        let mut stderr_path = path::PathBuf::new();
        stderr_path.push(temp_dir);
        stderr_path.push(stderr_filename);
        let stderr = fs::File::create(stderr_path).unwrap();

        children.push(
            process::Command::new(&byztime_bin_path)
                .arg(&config_path)
                .stderr(stderr)
                .spawn()
                .unwrap()
                .into(),
        );
        thread::sleep(time::Duration::from_nanos(200_000_000));
    }

    //Let everyone run for 3 seconds then send SIGTERM
    thread::sleep(time::Duration::from_secs(3));
    for child in &children {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .unwrap();
    }

    //Give a second to handle the SIGTERM, then send SIGKILL
    thread::sleep(time::Duration::from_secs(1));
    for child in &mut children {
        let _ = child.kill();
    }

    //Collect exit status and assert success
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(output.stderr.is_empty());
        if !output.status.success() {
            panic!("Output status: {}", output.status)
        }
    }

    //Assert absence of errors in the log files
    for log_file in &["alice.log", "bob.log", "charlie.log", "dave.log"] {
        let mut log_path = path::PathBuf::new();
        log_path.push(temp_dir);
        log_path.push(log_file);
        let log_contents = String::from_utf8(fs::read(&log_path).unwrap()).unwrap();
        assert!(log_contents.find("ERROR").is_none());
    }

    let mut mins = Vec::new();
    let mut ests = Vec::new();
    let mut maxs = Vec::new();
    let mut spans = Vec::new();

    let mut summary_path = path::PathBuf::new();
    summary_path.push(temp_dir);
    summary_path.push("summary");
    let mut summary_file = fs::File::create(&summary_path).unwrap();

    //Read the timedata files left behind
    for timedata_file in &[
        "alice.timedata",
        "bob.timedata",
        "charlie.timedata",
        "dave.timedata",
    ] {
        let mut timedata_path = path::PathBuf::new();
        timedata_path.push(temp_dir);
        timedata_path.push(timedata_file);

        let ctx = byztime::ConsumerContext::open(timedata_path.as_ref()).unwrap();
        let (min, est, max) = ctx.offset().unwrap();
        mins.push(min);
        ests.push(est);
        maxs.push(max);
        spans.push(max - min);

        writeln!(
            summary_file,
            "{}: min = {}; est = {}; max = {}; span = {}",
            timedata_file,
            min,
            est,
            max,
            max - min
        )
        .unwrap();
    }

    mins.sort();
    ests.sort();
    maxs.sort();
    spans.sort();

    writeln!(summary_file, "").unwrap();
    writeln!(summary_file, "Worst span: {}", spans[3]).unwrap();
    writeln!(summary_file, "Dispersion: {}", ests[3] - ests[0]).unwrap();

    //Assert that all error bounds are reasonbaly small
    for span in spans {
        assert!(span > byztime::Timestamp::new(0, 0));
        assert!(span < byztime::Timestamp::new(0, SPAN_LIMIT));
    }

    //Assert that all error ranges overlap
    assert!(maxs[0] > mins[3]);

    //Assert that all estimates agree reasonably
    assert!(ests[3] - ests[0] < byztime::Timestamp::new(0, DISPERSION_LIMIT));
}
