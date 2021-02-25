# Byztime

Byztime is a
[Byzantine-fault-tolerant](https://en.wikipedia.org/wiki/Byzantine_fault)
protocol for synchronizing time among a group of peers, without
reliance on any external time authority. The time kept by Byztime is
simply a counter that advances at a rate of something very close to
one unit per second, such that all nodes are in close agreement as
to its current value. Byztime timestamps have no well-defined epoch.
If all nodes have correctly-set system clocks when first
initialized, then Byztime will initially match POSIX time, but will
eventually drift away from it since 1. there is no external source
keeping it in sync, and 2. Byztime's timescale lacks leap seconds.

Byztime's algorithm is focused on keeping its *worst-case* error ---
the absolute distance between any two correct nodes' estimate of the
current time --- as small as possible. It achieves this somewhat at
the expense of *typical-case* error, using only the single
highest-quality time sample from each peer rather than combining many
samples to smooth out network jitter. In the worst case, the
difference between two correct nodes' clocks will asymptotically
converge toward 4δ + 4ερ, where δ is the one-way network latency
between the two farthest-spaced peers, ε is the (dimensionless) drift
rate of correct nodes' hardware clocks, and ρ is the polling
interval. If all nodes behave honestly, the bound improves to 2δ + 2ερ
and will be reached after a single round of the protocol rather than
converging asymptotically.

Byztimed runs completely independently of NTP, and a bad NTP time
source will not disrupt Byztime. This comes with a minor caveat: just
before the daemon shuts down it records the the current offset between
Byztime time and system time, and uses this offset to re-initialize
its estimate following a reboot. The only time this particularly
matters is if many nodes reboot simultaneously and the network loses
quorum. What happens in this case depends somewhat on NTP and what
order things start up in at boot time. If Byztime starts before NTP
starts and shuts down only after NTP shuts down, then the continuity
of the Byztime timescale will be as good as the RTC and the CMOS
battery of the restarting nodes, but no better. On the other hand if
NTP is allowed to stabilize the system clock before Byztime starts up,
then the continuity of the Byztime scales will be as good as its NTP
sources — which is probably a lot better than your RTC, but could be
arbitrarily bad if the NTP source is faulty. Again, this only becomes
an issue if Byztime loses quorum, meaning ⅓ or more of the network
reboots at once.

Byztime also currently relies on the system time for determining
whether an X.509 certificate is expired. Once
[Roughtime](https://tools.ietf.org/html/draft-ietf-ntp-roughtime)
matures a bit we may consider integrating a Roughtime client into
byztimed for certificate validation purposes.

## Build

Byztime is built like any standard [Rust](https://rust-lang.org)
crate. The easiest way to install byztimed is to get it from
[crates.io](https://crates.io) via
[`cargo`](https://doc.rust-lang.org/cargo/getting-started/installation.html):

    cargo install byztimed

If you prefer to check out and build this repo, note that `byztimed` includes
[`libbyztime`](https://github.com/akamai-contrib/libbyztime)
as a submodule, so be sure to clone with `git clone
--recurse-submodules`, or run `git submodule update --init
--recursive` if you have already cloned without the
`--recurse-submodules` option.

Byztime is tested against Rust's stable channel, but compilers
significantly older than the current stable will probably work. The
most recent version known not to work is 1.38 (because we rely on
async/await, which stabilized in 1.39).

Byztimed currently runs only on Linux, and is well-tested only on
AMD64. Other CPU architectures *should* work; please file a bug
ticket if you encounter any issues. We hope to eventually support
more operating systems, but this will be an uphill battle because
Byztime depends on timekeeping facilities that currently only
Linux provides. The effort to improve portability will likely require
contributing some new functionality to other OS kernels.

## Usage

Run byztimed as `byztimed <path-to-config-file>`. See
[CONFIG.md](https://github.com/akamai-contrib/byztimed/CONFIG.md)
for configuration file syntax.

[`libbyztime`](https://github.com/akamai-contrib/libbyztime)
is the C client library for consuming time from `byztimed`. See its
`byztime.h` file for API documentation. The `byztime` crate within
this repo provides idiomatic Rust bindings to libbyztime and its
documentation can be read on [docs.rs](https://docs.rs/byztime).

## Protocol overview

Although it is fundamentally a peer-to-peer protocol, Byztime uses a
client-server communication pattern, with each node acting as both a
client and a server to each other node. A client-only operation mode,
wherein a node synchronizes itself to the consensus but does not vote
in it, is also supported.

Byztime uses [Network Time
Security](https://www.rfc-editor.org/rfc/rfc8915.html) (NTS) for
cryptographic link protection. Communication from each client to
each server begins by the client initiating a TLS handshake and then
using NTS-KE to negotiate shared keys and obtain NTS cookies. After
NTS-KE is complete, the TLS connection closes and the remainder of
the protocol runs over UDP. NTS provides message-level authenticated
encryption. It provides replay protection for the client, but not
for the server. The server never updates any state in response to a
message from a client, so processing replays is harmless. For the
remainder of this overview, we'll take the abstraction of
authenticated encryption for granted and omit NTS-related machinery
from our descriptions.

Each node is assumed to be equipped with a *local clock* which
counts the time elapsed since some arbitrary epoch such as when the
system last booted. One node's local clock has no *a priori* known
relationship to another's. Rather, this relationship is discovered
through the execution of the protocol.  The shared time that nodes
seek to synchronize to is called the *global clock*. Nodes maintain
an estimate of their *global offset*, which is the difference
between the global clock and their local clock. The local clock never
receives any adjustments; only the global offset does.

The protocol proceeds by each node periodically sending a query to
each of its peers, and the peer sending a response which includes a
snapshot of its local clock and its current estimate of its global
offset. Each query/response volley is called a *measurement*.

The protocol uses the following global parameters:

1. `N`: the number of nodes participating in consensus.

2. `f`: the number of faulty nodes that can be tolerated.
    `f = floor((N-1)/3)`.

3. `drift`: a dimensionless number giving an upper bound on how fast
    or slow a correct node's local clock might be. For example if `drift`
    is 50e-6 then the clock might drift by up to 50µs per second.

Each node keeps the following state:

1. The `era` of its local clock. This is a randomly-generated
   identifier which changes if the local clock loses its state,
   *e.g.* after a reboot.

2. `global_offset`: The node's estimate of the offset between the
    global clock and its local clock: `local_clock() + global_offset
    == estimate of global clock`.

3. `error`: The maximum absolute difference between the above
    estimate of the global clock and its true value.

4. `last_update`: The local clock time at which `global_offset` and
   `error` were last updated.

And then for each of its peers:

5. `peer.era`: The peer's clock era as of the last time it communicated.

6. `peer.local_offset`: The node's estimate of the offset between
    its local clock and the peer's local clock: `local_clock() +
    peer.local_offset == estimate of peer's local clock`.

7. `peer.global_offset`: The peer's estimate of the offset between
    *its own* local clock and the global clock, as of the last time
    it communicated.

8. `peer.rtt`: The round trip time of the current "best" measurement
    of the peer's clock. This measurement is the one on which
    `peer.local_offset` is based.

9. `peer.origin_time`: The local clock time at which the query which
    led to the current best measurement was sent.

10. `peer.inflight_id`: The random unique identifier associated with
    a query, if any, that is currently awaiting a response.

11. `peer.inflight_origin_time`: The local clock time at which the
    current in-flight query (if any) was sent.

There is some additional state related to NTS — a cache of cookies
and shared keys — which works basically the same way as it does for
NTP and we'll disregard it for the purposes of this explanation.

At first run, nodes initialize `global_offset` such that the global
clock matches their real-time clock. They periodically check the
offset between the two and persist this offset to disk. This
persisted value is used to recover a rough value with which to
reinitialize `global_offset` after a reboot, but the error bounds
on offsets recovered in this manner are considered infinite.

Once per configured polling interval, clients send a query message to
each of their peers, containing just a randomly-generated unique
identifier. The sender updates `peer.inflight_id` and
`peer.inflight_origin_time` to reflect the content of the packet and
the time at which it was sent. If there was already another query in
flight, the old query is assumed to have been dropped by the network
and the new `inflight_id` and `inflight_origin_time` values
overwrite the old ones.

Servers respond immediately to any query they receive. The response
contains:

1. `response_id`: A copy of the query's unique identifier.

2. `response_local`: A snapshot of the server's local clock.

3. `response_era`: The server's `era`.

4. `response_global_offset`: The server's `global_offset`.

When the client receives the response, it processes it as follows:

1. Set `now` to a snapshot of the local clock at the moment the
   response was received.

2. Verify that `peer.inflight_id` is non-null and matches
   `response_id`. If not, discard the response. Otherwise, set
   `peer.inflight_id` to null and continue.

3. Set `peer.global_offset` to `response_global_offset`.

4. Compute `rtt` as `now - peer.inflight_origin_time`.

5. If this is the first response seen so far from this peer, or if
    `peer.era` does not match the era contained in the response,
    skip to step 8.

6. Compute the following lower-is-better quality metric for the
    current best measurement we have from this peer:
    `Q = peer.rtt/2 + 2 * drift * (now - peer.origin_time)`. This 
    represents the worst-case error in estimating the offset between
    this node's local clock and the peer's local clock, taking into account
    network asymmetry and clock drift. Drift is multiplied by 2
    because the two clocks could each be drifting in opposite
    directions.

7. Compute this quality metric for the new measurement: 
    `Q' = rtt/2 + 2 * drift * (now - peer.inflight_origin_time)`. If `Q' > Q`,
      then the old measurement is better than the new one, so keep
      it and return without further processing.

8. Set `peer.rtt` to `rtt`, `peer.origin_time` to
   `peer.inflight_origin_time`, and `peer.era` to `response_era`.

9. Set `peer.local_offset` to `response_clock + rtt/2 - now`.

Now with the newly updated clock values from the peer, recompute
`global_offset` and `error`:

10. For each peer `p`, compute an estimate `est = p.local_offset +
    p.global_offset` and error `err = p.rtt/2 + 2 * drift * (now - p.origin_time)`,
    giving an interval `(est - err, est + err)`. Create lists of all resulting
    minima and maxima.

11. If we ourselves are a participant in consensus, insert
    `global_offset` into the list of minima and the list of maxima.

12. Sort both lists. Discard the `f` lowest minima and the `f`
    highest maxima. Let `min'` equal the lowest remaining minimum
    and `max'` equal the highest remaining maximum. Let
    `global_offset' = (max' + min')/2`. Let `error' = (max' - min')/2`.
    This averaging method — discarding the `f` highest and
    lowest and taking the midpoint of the remaining range — is due
    to ["A New Fault-Tolerant Algorithm for Clock Synchronization"
    (Welch and Lynch
    1988)](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.462.89&rep=rep1&type=pdf)
    and is crucial for achieving Byzantine fault tolerance.

13. Determine whether the new global offset and error are consistent
    with the old one. Let `age = now - last_update`. Let `min =
    global_offset - error` and let `max = global_offset + error`.
    Let `drift_limit = 2 * age * drift`. Now check that
    `min' > min - drift_limit` and `max' < max + drift_limit`. If this
    check fails, return without further processing. (This step is not
    necessary for ensuring synchronization, but without it, a MitM
    adversary could cause time throughout the network to advance
    too quickly or too slowly, by delaying query messages but
    not response messages or vice versa.)

14. Set `last_update` to `now`, `global_offset` to `global_offset'`,
    and `error` to `error'`.

This completes our description of the protocol. Applications
consuming time from Byztime query the current values of
`global_offset`, `error`, and `last_update`. The global time is
`local_time + global_offset`, with error bounds of
`±(error + 2*drift*(local_time - last_update))`.

Estimates of global time are not frequency-stable: they jump
discontinuously with each update and can move backward. It's up to
the application how to deal with this. `libbyztime` includes support
for clamping the results of successive calls to `get_global_time()`
to make them consistent with each other.

## Caveats

Akamai has been using Byztime in business-critical applications
since early 2020 and it has been very stable for us. However, until
two specific issues are resolved, this software should be considered
beta:

1. We are likely to make some backward-incompatible changes to
   Byztime's wire protocol. Byztime currently uses [NTS-KE
   codepoints](https://www.iana.org/assignments/nts/nts.xhtml) in
   the Experimental Use range; we plan to obtain and use permanent
   allocations from IANA. We also will likely change the format of
   Byztime's time packets, currently based on Protobufs, to a
   bespoke fixed-field format, in order to make parsing more
   predictable and make it easier to ensure to that request size
   matches response size. We plan to have a single flag-day release
   that makes all these changes at once, and then commit to
   backward-compatibility thereafter.

2. Some of Byztime's statistics-and-health reporting capabilities
   have have been removed for this open-source release because they
   depend on Akamai-internal infrastructure to function.  We plan
   to redesign and reimplement this functionality around open
   standards.
