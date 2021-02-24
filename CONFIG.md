# Configuring byztimed

This file documents the configuration file used by
byztimed. Byztimed's configuration file is JSON. Here is an example
that uses every available option:

```
{
    "timedata": "/path/to/my/timedata",
    "secret_store": "/path/to/my/secret_store/",
    "ro_mode": false,
    "bind_host": "198.51.100.4",
    "bind_port": 1021,
    "key": "/path/to/alice.example.com.key",
    "cert": "/path/to/alice.example.com.crt",
    "authorities": "/path/to/trent.pem",
    "poll_interval": 64,
    "drift_ppb": 100000,
    "logging": {
        "STDERR": "error",
        "/var/log/byztimed.log": "info"
    },
    "log_format": "{d} {l} {t} - {m}{n}",
    "peers": {
        "bob": {
            "host": "192.0.2.1"
            "port": 1021,
            "cert_name": "bob.example.com",
            "dist": 300000,
        },
        "charlie": {
            "host": "charlie.example.com",
            "port": 1021,
            "dist": 250000,
            "authorities": "/path/to/a_different_ca.pem",
        },
        "dave": {
            "host": "dave.example.com",
            "port": 1021,
            "dist": 750000,
        }
    }
}
```

## Global section

The following options can appear at the top level of the file.

### `timedata`

**string, required**. Path to the timedata file. This file will be
mapped into shared memory and used for communication between byztimed
and its clients. If the file not exist, it will be created, and if it
appears to be corrupt it will be rewritten. The file must be writable
by byztimed and readable by its clients.

### `secret_store`

**string, required**. Path to the secret store. Must be a directory
and must exist; byztimed will populate it on first startup but the
user is responsible for setting appropriate permissions on the
directory.

The secret store is just a cache and its contents can always be
repopulated if lost, though if you have a very large number of nodes
this may be time-consuming. Paranoid users may wish to place it on a
tmpfs to prevent its contents from touching disk.

### `ro_mode`

**boolean, optional**; defaults to `false`. When true, the server
operates in read-only mode, polling its peers but not participating in
consensus.

### `bind_host`

**string, optional**; defaults to wildcard interface. Must be a
well-formed IPv4 or IPv6 address. Tells byztimed what interface to
bind to for its server.

### `bind_port`

**integer, required** unless running in read-only mode. Tells byztimed
what port to bind to for its server. The byztime protocol uses both
TCP (for key establishment) and UDP (for time packets). The same port
number is used for both.

### `key`

**string, required** unless running in read-only mode. Path to a file
containing your server's private key, in PKCS#8 PEM format.

*Note*: well-formed PKCS#8 PEM keys begin with `-----BEGIN PRIVATE
KEY-----`. If your key has some other heading, like `-----BEGIN RSA
PRIVATE KEY-----` or `-----BEGIN EC PARAMETERS-----` it's in the
wrong format and won't work. Pipe it through `openssl pkcs8 -topk8
-nocrypt` to convert it. (See <https://github.com/ctz/rustls/issues/332>)

### `cert`

**string, required** unless running in read-only mode. Path to a file
containing your server's X.509 certificate and any intermediate CAs, in
PEM format.

### `authorities`

**string, required** unless specified individually
for every peer. Path to a file containing a list of trusted
certificate authorities in PEM format.

### `poll_interval`

**float, optional**, defaults to *8.0*. How often to poll each peer,
in seconds.

### `drift_ppb`

**integer, optional**, defaults to 250000. Upper bound on how quickly
our system clock drifts, in parts per billion. Used in computing error
bounds.

### `logging`

**map, optional**, defaults to `{"STDERR": "info"}`. Each key is
either the path to a log file or the special, case-sensitive string
`"STDOUT"` or `"STDERR"`. Each value is one of `"error"`, `"warn"`,
`"info"`, `"debug"`, or `"trace"`, specifying the minimum severity of
log messages to output. Only debug builds will ever emit debug or
trace messages.

### `log_format`

**string, optional**, defaults to `"{d} {l} {t} - {m}{n}"`. A
[log4rs format string](https://docs.rs/log4rs/0.12.0/log4rs/encode/pattern/index.html#formatters)
controlling the format of log files.

### `peers`

**map**; see next section for its format.

## Peers section

Each key in the `"peers"` map is an arbitrary string identifying the
peer; it will be used in log messages. Each value is another map
containing the following entries.

### `host`

**string, required**. IP address or hostname where the peer is listening.

### `port`

**integer, required**. Port number where the peer is listening.

### `dist`

**integer, optional**, defaults to 0. A lower bound on this peer's
physical distance from us, given in meters. Setting this option will
allow tighter error bounds to be achieved. (Again, set this to a
*lower bound* to accomodate any uncertainty. The higher it is set,
the tighter the error bounds that will be reported. If it is set
too high, the error bounds may then become invalid).

### `cert_name`

**string, optional**, defaults to being the same as `host`. The DNS
name to expect when validating the peer's certificate. (Must be a DNS
name; validation of certificates issued to IP addresses is not
currently supported).

### `authorities`

**string, optional**, defaults to the setting from the global section.
Path to a file containing a list of certificate authorities, in PEM
format, trusted to identify this peer.