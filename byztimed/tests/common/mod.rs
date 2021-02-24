//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::ops;
use std::process;
use std::sync::Mutex;

lazy_static! {
    static ref CUR_PORT: Mutex<u16> = Mutex::new(49151);
}

///Find available ports to use for byztimed tests
///
/// Returns a vector of `num_ports` port numbers that are available
/// for both UDP and TCP. Every invocation will return a set not used
/// by any prior invocation, so that if this function is used by
/// multiple concurrent tests they won't race with each other. There
/// is inevitably still a race with other unrelated processes on the
/// system which might grab the ports between when we call this
/// function and when byztimed starts up.
pub fn find_ports(num_ports: usize) -> Vec<u16> {
    let mut ports = Vec::with_capacity(num_ports);
    let mut cur_port = CUR_PORT.lock().unwrap();

    while ports.len() < num_ports {
        if *cur_port == 65535 {
            panic!("Couldn't find enough available ports");
        }
        *cur_port += 1;
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), *cur_port);
        let udp_result = UdpSocket::bind(&addr);
        let tcp_result = TcpListener::bind(&addr);
        if udp_result.is_ok() && tcp_result.is_ok() {
            ports.push(*cur_port);
        }
    }

    ports
}

///Wrapper around a Child that kills it and collects it exit status
/// when dropped
pub struct ChildWrapper {
    child: Option<process::Child>,
}

impl ChildWrapper {
    pub fn wait_with_output(mut self) -> io::Result<process::Output> {
        mem::replace(&mut self.child, None)
            .unwrap()
            .wait_with_output()
    }
}

impl Drop for ChildWrapper {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            if child.try_wait().unwrap().is_none() {
                let _ = child.kill();
                child.wait().unwrap();
            }
        }
    }
}

impl ops::Deref for ChildWrapper {
    type Target = process::Child;
    fn deref(&self) -> &process::Child {
        self.child.as_ref().unwrap()
    }
}

impl ops::DerefMut for ChildWrapper {
    fn deref_mut(&mut self) -> &mut process::Child {
        self.child.as_mut().unwrap()
    }
}

impl From<process::Child> for ChildWrapper {
    fn from(child: process::Child) -> ChildWrapper {
        ChildWrapper { child: Some(child) }
    }
}
