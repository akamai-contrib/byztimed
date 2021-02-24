//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//! Core state machine
//!
//! This module implements the core logic of Byztime, basically what's
//! described in in the Byztime paper. The types it passes in and out
//! are just abstract representations of Byztime messages; it doesn't
//! do any network IO or know anything about wire formats or
//! cryptography. It is, however, responsible for updating the timedata
//! file, so state updates will be visible to clients.

use crate::config::*;
use crate::peer_name::PeerName;
use byztime::*;
use std::collections::*;
use std::io;
use std::iter::FromIterator;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

///Unique identifier for a time request
pub type UniqueId = [u8; 16];

///The time that it takes for light to travel 10**9 meters through a vacuum
fn light_gigameter() -> Timestamp {
    Timestamp::new(3, 335_640_952)
}

///Everything we know about the state of a particular peer's clock
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct PeerClock {
    ///Era of peer's clock
    era: Era,
    ///Estimate of peer's local clock minus our local clock
    local_offset: Timestamp,
    ///Peer's estimate of global clock minus peer's local clock
    global_offset: Timestamp,
    ///Round-trip time of best clock sample
    rtt: Timestamp,
    ///Time (according to local clock) when best clock sample was acquired
    origin_time: Timestamp,
}

impl PeerClock {
    ///Returns an estimate of (global clock - our local clock) based on information from this peer
    fn offset(&self) -> Timestamp {
        self.local_offset + self.global_offset
    }

    ///Returns the maximum absolute estimation error of local_offset.
    ///
    /// * `drift_ppb`: Upper bound on rate of clock drift, in parts per billion
    /// * `dist`: Lower bound on our physical distance from the peer, in meters
    /// * `as_of`: Local time as of which to compute the error bound
    fn error(&self, drift_ppb: i64, dist: i64, as_of: &Timestamp) -> Timestamp {
        let age = *as_of - self.origin_time;
        let light_time = light_gigameter().scale(2 * dist);
        self.rtt.halve() - light_time.halve() + age.scale(2 * drift_ppb)
    }
}

///Everything we know about a particular peer
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct PeerState {
    ///Physical distance in meters
    dist: i64,
    ///Unique-id of any in-flight query to this peer
    inflight: Option<UniqueId>,
    ///Origin timestamp of any in-flight query to this peer
    origin_time: Option<Timestamp>,
    ///State of peer's clock, if known
    clock: Option<PeerClock>,
}

///Semantic representation of a Byztime query packet
#[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Query {
    ///An arbitrary bytestring uniquely identifying this query
    pub unique_id: UniqueId,
}

#[cfg(test)]
impl Arbitrary for Query {
    fn arbitrary<G: Gen>(g: &mut G) -> Query {
        let mut unique_id = [0; 16];
        for byte in &mut unique_id {
            *byte = u8::arbitrary(g);
        }
        Query { unique_id }
    }
}

///Semantic representation of a Byztime response packet
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Response {
    ///Unique identifer that was passed in the corresponding query
    pub unique_id: UniqueId,
    ///Era of our local clock
    pub era: Era,
    ///Our local clock value
    pub local_clock: Timestamp,
    ///Our estimate of (global clock - our local clock)
    pub global_offset: Timestamp,
}

#[cfg(test)]
impl Arbitrary for Response {
    fn arbitrary<G: Gen>(g: &mut G) -> Response {
        let mut unique_id = [0; 16];
        g.fill_bytes(&mut unique_id);
        Response {
            unique_id,
            era: Era::arbitrary(g),
            local_clock: Timestamp::arbitrary(g),
            global_offset: Timestamp::arbitrary(g),
        }
    }
}

///The Byztime state machine
pub struct CoreState {
    ///Read-write handle to the timedata file
    ctx: ProviderContext,
    ///Whether we're in read-only mode (just querying consensus, not participating)
    ro_mode: bool,
    ///Upper bound on clock drift rate in parts per billion
    drift_ppb: i64,
    ///Our clock era
    era: Era,
    //Map of UniqueIds to the peer they are in flight for
    inflight: HashMap<UniqueId, PeerName>,
    ///State of each peer
    peers: HashMap<PeerName, PeerState>,
}

///Health statistics
#[derive(Debug, Clone)]
pub struct HealthStats {
    pub real_time: Timestamp,
    pub global_time: Timestamp,
    pub max_error: Timestamp,
    pub est_error: f64,
}

impl CoreState {
    ///Initialize ourselves from the configuration file
    pub fn initialize(config: &Config) -> io::Result<CoreState> {
        Ok(CoreState {
            ctx: ProviderContext::open(&config.timedata)?,
            ro_mode: config.ro_mode,
            drift_ppb: config.drift_ppb,
            era: Era::get()?,
            inflight: HashMap::new(),
            peers: HashMap::from_iter(config.peers.iter().map(|(peer_name, peerconfig)| {
                (
                    peer_name.clone(),
                    PeerState {
                        dist: peerconfig.dist,
                        inflight: None,
                        origin_time: None,
                        clock: None,
                    },
                )
            })),
        })
    }

    ///Called upon receiving a query, and returns the corresponding
    ///response. The caller is responsible for promptly transmitting
    ///the response to its proper destination.
    pub fn on_query(&self, query: &Query) -> io::Result<Response> {
        Ok(Response {
            unique_id: query.unique_id,
            local_clock: Timestamp::local_time()?,
            era: self.era,
            global_offset: self.ctx.offset_quick(),
        })
    }

    ///Called at each polling interval for each peer, and returns a
    ///query to send to that peer. The caller is responsible for
    ///prompty transmitting the query to its proper destination.
    pub fn on_tick<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        peer_name: &PeerName,
        rng: &mut R,
    ) -> io::Result<Query> {
        let peerstate = self.peers.get_mut(peer_name).expect("unknown peer");
        let mut unique_id = [0; 16];
        rng.fill_bytes(&mut unique_id);

        let result = Query { unique_id };
        if let Some(old_inflight) = peerstate.inflight {
            self.inflight.remove(&old_inflight);
        }

        self.inflight.insert(unique_id, peer_name.clone());
        peerstate.inflight = Some(unique_id);
        peerstate.origin_time = Some(Timestamp::local_time()?);
        Ok(result)
    }

    ///Called periodically in single-node configurations to keep the timedata
    ///file's error bounds updated
    pub fn on_single_node_tick(&mut self) -> io::Result<()> {
        let now = Timestamp::local_time()?;
        self.update_offset(now)
    }

    ///Called just before actually sending a query over the network,
    ///to give us a more accurate origin timestamp.
    pub fn on_departure(&mut self, peer_name: &PeerName) -> io::Result<()> {
        let peerstate = self.peers.get_mut(peer_name).expect("unknown peer");
        peerstate.origin_time = Some(Timestamp::local_time()?);
        Ok(())
    }

    pub fn lookup_peer(&self, unique_id: &UniqueId) -> Option<PeerName> {
        self.inflight.get(unique_id).cloned()
    }

    ///Called upon receiving a response. Updates state, including
    ///updating the timedata file.
    pub fn on_response(&mut self, response: &Response, dest_time: Timestamp) -> io::Result<()> {
        if let Some(peer) = self.inflight.remove(&response.unique_id) {
            self.update_peer_state(response, &peer, dest_time)?;
            self.update_offset(dest_time)
        } else {
            Ok(())
        }
    }

    pub fn get_health_stats(&self) -> io::Result<HealthStats> {
        let real_time = Timestamp::real_time()?;
        let local_time = Timestamp::local_time()?;
        let (min, offset, max) = self.ctx.offset()?;
        let global_time = local_time + offset;

        let max_error = max.halve() - min.halve();

        let n_peers = self.peers.len();
        let n = if self.ro_mode { n_peers } else { n_peers + 1 };
        let f = (n + 1) / 3;
        let mut peer_squared_offsets = Vec::from_iter(self.peers.values().map(|peer| {
            peer.clock.as_ref().map_or(std::f64::INFINITY, |clock| {
                let offset = clock.offset() - self.ctx.offset_quick();
                let float_offset =
                    offset.seconds() as f64 + offset.nanoseconds() as f64 / 1_000_000_000 as f64;
                float_offset * float_offset
            })
        }));
        peer_squared_offsets.sort_by(|a, b| a.partial_cmp(b).unwrap());
        peer_squared_offsets.truncate(n - f);
        let est_error =
            peer_squared_offsets.iter().sum::<f64>().sqrt() / (peer_squared_offsets.len() as f64);

        Ok(HealthStats {
            real_time,
            global_time,
            max_error,
            est_error,
        })
    }

    ///Update the offset between the global clock and the system clock.    
    ///
    ///The only thing this is used for is persistence across reboots;
    /// so that if we have just rebooted and not yet re-contacted any
    /// of our peers, we can use system time to give a sane estimate
    /// of global time, albeit one with infinite error bounds.
    pub fn update_real_offset(&mut self) -> io::Result<()> {
        self.ctx.update_real_offset()
    }

    ///Update our `PeerClock` based on a response from that peer. Caller is responsible
    ///for checking that the response corresponds to an in-flight request.
    fn update_peer_state(
        &mut self,
        response: &Response,
        peer_name: &PeerName,
        dest_time: Timestamp,
    ) -> io::Result<()> {
        let peerstate = self.peers.get_mut(peer_name).expect("unknown peer");

        //Check when the request corresponding to this response was sent
        let origin_time = peerstate
            .origin_time
            .expect("Called update_peer_state with nothing in flight");
        peerstate.inflight = None;
        peerstate.origin_time = None;

        let rtt = dest_time - origin_time; //Round trip time
        let xmit_time = origin_time.halve() + dest_time.halve(); //Estimate of when the response left the peer
        let new_quality = rtt.halve() + rtt.scale(2 * self.drift_ppb); //Quality metric of this sample (lower is better)

        peerstate.clock = Some(match &peerstate.clock {
            //If we have no sample other than this one, accept it.
            None => PeerClock {
                era: response.era,
                local_offset: response.local_clock.saturating_sub(xmit_time),
                global_offset: response.global_offset.saturating_normalize(),
                rtt,
                origin_time,
            },

            //Otherwise, only accept it if it's of better quality than what we already have.
            Some(peer_clock) => {
                let old_age = origin_time - peer_clock.origin_time;
                let old_quality = peer_clock.rtt.halve() + old_age.scale(2 * self.drift_ppb);
                if new_quality < old_quality || response.era != peer_clock.era {
                    //Either it's of better quality (remember, lower
                    //is better), or the peer's clock era has changed
                    //in which case whatever we had before is now
                    //worthless. Accept the sample.
                    PeerClock {
                        era: response.era,
                        local_offset: response.local_clock.saturating_sub(xmit_time),
                        global_offset: response.global_offset.saturating_normalize(),
                        rtt,
                        origin_time,
                    }
                } else {
                    //Otherwise, just update the peer's `global_offset` and
                    //leave everything else the same.
                    PeerClock {
                        era: peer_clock.era,
                        local_offset: peer_clock.local_offset,
                        global_offset: response.global_offset.saturating_normalize(),
                        rtt: peer_clock.rtt,
                        origin_time: peer_clock.origin_time,
                    }
                }
            }
        });

        Ok(())
    }

    ///Recompute our global offset estimate from newly-updated peer clocks.
    fn update_offset(&mut self, as_of: Timestamp) -> io::Result<()> {
        let (my_min, my_est, my_max) = self.ctx.offset()?;

        //From each peer, we obtain an estimate of
        //     (peer's estimate of (peer global clock - our local clock)),
        // which is computed as
        //      (our estimate of (peer's local clock - our local clock)) +
        //      (peer's estimate of (global clock - peer's local clock)).
        // Note the construction of this: we're estimating an estimate.
        //   The error bounds on *our* estimate are determined by network
        //   latency between ourself and the peer.

        //Enumerate lower bounds on the value described above.
        let mut minima = {
            let peer_min_iter = self
                .peers
                .values()
                .map(|ref peer_state| match &peer_state.clock {
                    None => {
                        //For any peer we haven't contacted since the
                        // last time the daemon restarted, we can
                        // safely substitute the aggregate lower bound
                        // computed from prior runs. If this the daemon's
                        // first startup since the last reboot, libbyztime
                        // will have inserted an INT_MIN-like lower bound
                        // for us.
                        my_min
                    }
                    Some(clock) => clock.offset().saturating_sub(clock.error(
                        self.drift_ppb,
                        peer_state.dist,
                        &as_of,
                    )),
                });

            //Include our own clock in the list only if we're a participant in consensus,
            //i.e., we're not running in read-only mode.
            if self.ro_mode {
                Vec::from_iter(peer_min_iter)
            } else {
                //We can estimate our *own* estimate perfectly, so the lower bound on my_est is just my_est.
                Vec::from_iter(peer_min_iter.chain(std::iter::once(my_est)))
            }
        };

        //Now do the same for upper bound
        let mut maxima = {
            let peer_max_iter = self
                .peers
                .values()
                .map(|ref peer_state| match &peer_state.clock {
                    None => my_max,
                    Some(clock) => clock.offset().saturating_add(clock.error(
                        self.drift_ppb,
                        peer_state.dist,
                        &as_of,
                    )),
                });

            if self.ro_mode {
                Vec::from_iter(peer_max_iter)
            } else {
                Vec::from_iter(peer_max_iter.chain(std::iter::once(my_est)))
            }
        };

        //Sort these bounds
        minima.sort_unstable();
        maxima.sort_unstable();

        //Compute f, the number of faulty peers we can tolerate
        let n_peers = self.peers.len();
        let n = if self.ro_mode { n_peers } else { n_peers + 1 };
        let f = (n - 1) / 3;

        //Now by discarding the f lowest lower bounds and the f highest upper bounds,
        // we can directly estimate (global clock - our local clock), rather than
        // estimating estimates like we have so far.
        let lo = minima[f]; //The f+1'th lowest lower bound
        let hi = maxima[n - 1 - f]; //The f+1'th highest upper bound
        let offset = lo.halve() + hi.halve(); //Midpoint of lo and hi
        let error = hi.halve() - lo.halve(); //Maximum absolute estimation error

        //Verify that the newly-computed estimate is consistent with
        //the old one to within the drift rate. If so, record it.
        let (old_offset, old_error, old_as_of) = self.ctx.offset_raw();
        let old_min = old_offset.saturating_sub(old_error);
        let old_max = old_offset.saturating_add(old_error);
        let new_min = lo;
        let new_max = hi;
        let age = as_of.saturating_sub(old_as_of);
        let max_drift = age.scale(2 * self.drift_ppb);

        if new_min >= old_min - max_drift && new_max <= old_max + max_drift {
            self.ctx.set_offset(offset, error, as_of)
        } else {
            Ok(())
        }
    }
}
