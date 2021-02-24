//Copyright 2020, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//! Byztime is a Byzantine-fault-tolerant protocol for synchronizing
//! time among a group of peers, without reliance on any external
//! authority. This crate wraps [byztime_sys] (which in turn wraps
//! the C library libbyztime) to provide an idiomatic Rust API for
//! communication from [byztimed](https://crates.io/crate/byztimed)
//! to applications which consume time from it.
//!
//! libbyztime employs a "blackboard" pattern of one-way
//! communication. The daemon writes time offsets and error bounds
//! to a *timedata* file, which is a regular file containing a
//! lock-free data structure. Consumers simply read from the file
//! without altering it or sending any sort of query to the daemon.
//!
//! Byztime recognizes three kinds of clocks:
//!
//! * The *local* clock is a hardware clock that represents the time
//!   elapsed since some arbitrary epoch, such as the last reboot.
//!   On Linux this is realized by `CLOCK_MONOTONIC_RAW`.
//!
//! * The *real* clock tracks wall time (`CLOCK_REALTIME`). Byztime
//!    mostly avoids relying on it but does use it for recovery if
//!    the network loses quorum in a mass reboot.
//!
//! * The *global* clock is the one that Byztime synchronizes. At
//!   first initialization it is set to the real clock. Eventually
//!   it should be expected to drift, though, because Byztime is
//!   designed to keep nodes synchronized only with each other and
//!   not with anything else.
//!
//! The Byztime daemon determines the offset between the global and
//! local clocks, a maximum error bound on that offset, and the
//! local time as of which that error bound is valid. It records
//! these values in the timedata file. Consumers read them and then
//! obtain the local time from the operating system. From these
//! inputs they can compute the global time, as well as recomputing
//! error bounds to account for any drift that may have occurred
//! since the last timedata update.
//!
//! Simple consumers will want to use this crate as follows:
//!
//! 1. Optionally, call [install_sigbus_handler].
//!
//! 2. Call [ConsumerContext::open] with the path to timedata file to
//!    obtain a `Context` object.
//!
//! 3. Optionally, call [Context::slew]. Sleep and retry in a loop
//!    until it succeeds.
//!
//! 4. Call [Context::global_time] to get a timestamp with error
//!    bounds.

use byztime_sys::*;
use std::cmp;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::ops;
use std::os::unix::ffi::OsStrExt;
use std::path;

#[cfg(any(test, feature = "with_quickcheck"))]
use quickcheck::{Arbitrary, Gen};
#[cfg(any(test, feature = "with_quickcheck"))]
use rand::Rng;

/// A timestamp with nanosecond resolution
#[derive(Debug, Copy, Clone)]
pub struct Timestamp(pub byztime_stamp);

/// A random identifier representing a clock era
///
/// Two timestamps obtained by calling [Timestamp::local_time] are
/// comparable iff they were obtained during the same era.
/// Generally, the era changes across reboots and is otherwise
/// constant.
#[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Era(pub [u8; 16]);

impl Era {
    /// Returns the current clock era.
    pub fn get() -> io::Result<Era> {
        let mut era: [u8; 16] = [0; 16];
        if unsafe { byztime_get_clock_era(era.as_mut_ptr()) } < 0 {
            Err(errno::errno().into())
        } else {
            Ok(Era(era))
        }
    }
}

impl Timestamp {
    ///Build a timestamp from a given count of `seconds` and `nanoseconds`
    pub fn new(seconds: i64, nanoseconds: i64) -> Timestamp {
        Timestamp(byztime_stamp {
            seconds,
            nanoseconds,
        })
    }

    ///Return the seconds portion of the timestamp
    pub fn seconds(self) -> i64 {
        self.0.seconds
    }

    ///Return the nanoseconds portion of the timestamp
    pub fn nanoseconds(self) -> i64 {
        self.0.nanoseconds
    }

    fn overflowing_normalize_assign(&mut self) -> bool {
        if unsafe { byztime_stamp_normalize(&mut self.0 as *mut byztime_stamp) } < 0 {
            assert_eq!(
                libc::EOVERFLOW,
                Into::<i32>::into(errno::errno()),
                "byztime_stamp_normalize: {}",
                errno::errno()
            );
            true
        } else {
            false
        }
    }

    /// Normalizes the timestamp such that 0 ≤ nanoseconds < 1_000_000_000.
    pub fn normalize(self) -> Timestamp {
        let (result, overflow) = self.overflowing_normalize();
        if overflow {
            panic!("timestamp overflow")
        };
        result
    }

    /// Normalizes the timestamp such that 0 ≤ nanoseconds <
    /// 1_000_000_000.
    ///
    /// Returns a tuple of the normalized timestamp along with a
    /// boolean indicating whether an arithmetic overflow occurred.
    /// If an overflow did occur then the 2s-complement wrapped
    /// value is returned.
    pub fn overflowing_normalize(mut self) -> (Timestamp, bool) {
        let overflow = self.overflowing_normalize_assign();
        (self, overflow)
    }

    /// Normalizes the timestamp such that 0 ≤ nanoseconds <
    /// 1_000_000_000. If an overflow occurs, returns the
    /// 2s-complement wrapped value.
    pub fn wrapping_normalize(self) -> Timestamp {
        let (result, _) = self.overflowing_normalize();
        result
    }

    fn saturating_normalize_assign(&mut self) -> bool {
        let seconds = self.seconds();
        if self.overflowing_normalize_assign() {
            if seconds > 0 {
                *self = Timestamp::max_value();
            } else {
                *self = Timestamp::min_value()
            }
            true
        } else {
            false
        }
    }

    /// Normalizes the timestamp such that 0 ≤ nanoseconds <
    /// 1_000_000_000.
    pub fn saturating_normalize(mut self) -> Timestamp {
        self.saturating_normalize_assign();
        self
    }

    /// Normalizes the timestamp such that 0 ≤ nanoseconds <
    /// 1_000_000_000, returning `None` if overflow occurred.
    pub fn checked_normalize(self) -> Option<Timestamp> {
        let (result, overflow) = self.overflowing_normalize();
        if overflow {
            None
        } else {
            Some(result)
        }
    }

    ///Return a timestamp representing the current local time
    ///
    ///"Local" here is in the Byztime sense of local to this machine,
    /// not the civil sense of local to a timezone.
    pub fn local_time() -> io::Result<Timestamp> {
        let mut ts = Timestamp::default();
        ts.local_time_assign()?;
        Ok(ts)
    }

    fn local_time_assign(&mut self) -> io::Result<()> {
        if unsafe { byztime_get_local_time(&mut self.0 as *mut byztime_stamp) } < 0 {
            Err(errno::errno().into())
        } else {
            Ok(())
        }
    }

    ///Return a timestamp representing the current real time, i.e., POSIX time
    pub fn real_time() -> io::Result<Timestamp> {
        let mut ts = Timestamp::default();
        ts.real_time_assign()?;
        Ok(ts)
    }

    fn real_time_assign(&mut self) -> io::Result<()> {
        if unsafe { byztime_get_real_time(&mut self.0 as *mut byztime_stamp) } < 0 {
            Err(errno::errno().into())
        } else {
            Ok(())
        }
    }

    fn overflowing_add_assign(&mut self, other: Timestamp) -> bool {
        let self_ptr = &mut self.0 as *mut byztime_stamp;
        let other_ptr = &other.0 as *const byztime_stamp;
        if unsafe { byztime_stamp_add(self_ptr, self_ptr, other_ptr) } < 0 {
            assert_eq!(
                libc::EOVERFLOW,
                Into::<i32>::into(errno::errno()),
                "byztime_stamp_add: {}",
                errno::errno()
            );
            true
        } else {
            false
        }
    }

    fn overflowing_sub_assign(&mut self, other: Timestamp) -> bool {
        let self_ptr = &mut self.0 as *mut byztime_stamp;
        let other_ptr = &other.0 as *const byztime_stamp;
        if unsafe { byztime_stamp_sub(self_ptr, self_ptr, other_ptr) } < 0 {
            assert_eq!(
                libc::EOVERFLOW,
                Into::<i32>::into(errno::errno()),
                "byztime_stamp_sub: {}",
                errno::errno()
            );
            true
        } else {
            false
        }
    }

    /// Calculates `self` + `rhs`.
    ///
    /// Returns a tuple of the addition along with a boolean indicating whether
    /// an arithmetic overflow occurred. If an overflow occurred then the wrapped
    /// value is returned.
    pub fn overflowing_add(mut self, rhs: Timestamp) -> (Timestamp, bool) {
        let overflow = self.overflowing_add_assign(rhs);
        (self, overflow)
    }

    /// Calculates `self` - `rhs`.
    ///
    /// Returns a tuple of the subtraction along with a boolean indicating whether
    /// an arithmetic overflow occurred. If an overflow occurred then the wrapped
    /// value is returned.
    pub fn overflowing_sub(mut self, rhs: Timestamp) -> (Timestamp, bool) {
        let overflow = self.overflowing_sub_assign(rhs);
        (self, overflow)
    }

    /// Checked addition of timestamps. Computes `self` + `rhs`,
    /// returning `None` if overflow occurred.
    pub fn checked_add(self, rhs: Timestamp) -> Option<Timestamp> {
        let (sum, overflow) = self.overflowing_add(rhs);
        if overflow {
            None
        } else {
            Some(sum)
        }
    }

    /// Checked subtractions of timestamps. Computes `self` - `rhs`,
    /// returning `None` if overflow occurred.
    pub fn checked_sub(self, rhs: Timestamp) -> Option<Timestamp> {
        let (diff, overflow) = self.overflowing_sub(rhs);
        if overflow {
            None
        } else {
            Some(diff)
        }
    }

    /// Wrapping addition of timestamps.  Computess `self` + `rhs`,
    /// wrapping around at the boundary of the type.
    pub fn wrapping_add(self, rhs: Timestamp) -> Timestamp {
        let (sum, _) = self.overflowing_add(rhs);
        sum
    }

    /// Wrapping subtraction of timestamps.  Computess `self` - `rhs`,
    /// wrapping around at the boundary of the type.
    pub fn wrapping_sub(self, rhs: Timestamp) -> Timestamp {
        let (diff, _) = self.overflowing_sub(rhs);
        diff
    }

    /// Saturating addition of timestamps. Computes `self` + `rhs`,
    /// saturating at numeric bounds instead of overflowing.
    pub fn saturating_add(self, rhs: Timestamp) -> Timestamp {
        let (sum, overflow) = self.overflowing_add(rhs);
        if overflow {
            if rhs > Timestamp::default() {
                Timestamp::max_value()
            } else {
                Timestamp::min_value()
            }
        } else {
            sum
        }
    }

    /// Saturating subtraction of timestamps. Computes `self` - `rhs`,
    /// saturating at numeric bounds instead of overflowing.
    pub fn saturating_sub(self, rhs: Timestamp) -> Timestamp {
        let (diff, overflow) = self.overflowing_sub(rhs);
        if overflow {
            if rhs < Timestamp::default() {
                Timestamp::max_value()
            } else {
                Timestamp::min_value()
            }
        } else {
            diff
        }
    }

    fn overflowing_scale_assign(&mut self, ppb: i64) -> bool {
        let self_ptr = &mut self.0 as *mut byztime_stamp;
        if unsafe { byztime_stamp_scale(self_ptr, self_ptr, ppb) } < 0 {
            assert_eq!(
                libc::EOVERFLOW,
                Into::<i32>::into(errno::errno()),
                "byztime_stamp_scale: {}",
                errno::errno()
            );
            true
        } else {
            false
        }
    }

    fn saturating_scale_assign(&mut self, ppb: i64) -> bool {
        let negated = (*self < Timestamp::default()) ^ (ppb < 0);
        if self.overflowing_scale_assign(ppb) {
            if negated {
                *self = Timestamp::min_value()
            } else {
                *self = Timestamp::max_value()
            }
            true
        } else {
            false
        }
    }

    /// Multiplies the timestamp by `ppb` parts per billion.
    ///
    /// Returns a tuple of the multiplication along with a boolean
    /// indicating whether an arithmetic overflow occurred. If an
    /// overflow occurred then the wrapped value is returned.
    pub fn overflowing_scale(mut self, ppb: i64) -> (Timestamp, bool) {
        let overflow = self.overflowing_scale_assign(ppb);
        (self, overflow)
    }

    /// Multiplies the timestamp by `ppb` parts per billion.
    pub fn scale(self, ppb: i64) -> Timestamp {
        let (result, overflow) = self.overflowing_scale(ppb);
        if overflow {
            panic!("timestamp overflow")
        } else {
            result
        }
    }

    /// Multiplies the timestamp by `ppb` parts per billion,
    /// returning `None` if overflow occurred.
    pub fn checked_scale(self, ppb: i64) -> Option<Timestamp> {
        let (result, overflow) = self.overflowing_scale(ppb);
        if overflow {
            None
        } else {
            Some(result)
        }
    }

    /// Multiplies the timestamp by `ppb` parts per billion,
    /// wrapping around at the limits of the type if overflow
    /// occurs.
    pub fn wrapping_scale(self, ppb: i64) -> Timestamp {
        let (result, _) = self.overflowing_scale(ppb);
        result
    }

    /// Multiplies the timestamp by `ppb` parts per billion,
    /// saturating at numeric bounds rather than overflowing.
    pub fn saturating_scale(mut self, ppb: i64) -> Timestamp {
        self.saturating_scale_assign(ppb);
        self
    }

    fn halve_assign(&mut self) {
        let self_ptr = &mut self.0 as *mut byztime_stamp;
        unsafe {
            byztime_stamp_halve(self_ptr, self_ptr);
        }
    }

    /// Divides the timestamp by two.
    pub fn halve(mut self) -> Timestamp {
        self.halve_assign();
        self
    }

    /// Returns the smallest (most negative) value representable by this type.
    pub fn min_value() -> Timestamp {
        Timestamp::new(i64::min_value(), 0)
    }

    /// Returns the largest value representable by this type.
    pub fn max_value() -> Timestamp {
        Timestamp::new(i64::max_value(), 0)
    }

    /// Returns half of the largest value representable by this
    /// type. This value is used as an error term when the clock
    /// is unsynchronized.
    pub fn max_error() -> Timestamp {
        Timestamp::new(i64::max_value() >> 1, 0)
    }
}

impl Default for Timestamp {
    fn default() -> Timestamp {
        Timestamp::new(0, 0)
    }
}

impl ops::Add for Timestamp {
    type Output = Timestamp;
    fn add(mut self, other: Timestamp) -> Timestamp {
        let overflow = self.overflowing_add_assign(other);
        if overflow {
            panic!("timestamp overflow")
        } else {
            self
        }
    }
}

impl ops::Sub for Timestamp {
    type Output = Timestamp;
    fn sub(mut self, other: Timestamp) -> Timestamp {
        let overflow = self.overflowing_sub_assign(other);
        if overflow {
            panic!("timestamp overflow")
        } else {
            self
        }
    }
}

impl ops::AddAssign for Timestamp {
    fn add_assign(&mut self, other: Timestamp) {
        if self.overflowing_add_assign(other) {
            panic!("timestamp overflow")
        }
    }
}

impl ops::SubAssign for Timestamp {
    fn sub_assign(&mut self, other: Timestamp) {
        if self.overflowing_sub_assign(other) {
            panic!("timestamp overflow")
        }
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Timestamp) -> cmp::Ordering {
        let self_ptr = &self.0 as *const byztime_stamp;
        let other_ptr = &other.0 as *const byztime_stamp;
        let ret = unsafe { byztime_stamp_cmp(self_ptr, other_ptr) };
        ret.cmp(&0)
    }
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Timestamp) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Timestamp {
    fn eq(&self, other: &Timestamp) -> bool {
        self.cmp(other) == cmp::Ordering::Equal
    }
}

impl Eq for Timestamp {}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let normed = self.normalize();
        write!(f, "{}.{:09}", normed.seconds(), normed.nanoseconds())
    }
}

///Look up the current estimated offset (global clock - local clock) and error bounds
///and store them into the provided references.
fn offset_assign(
    ctx: *mut byztime_ctx,
    min: Option<&mut Timestamp>,
    est: Option<&mut Timestamp>,
    max: Option<&mut Timestamp>,
) -> io::Result<()> {
    let min_ptr = match min {
        Some(min_ref) => &mut min_ref.0 as *mut byztime_stamp,
        None => std::ptr::null_mut(),
    };

    let est_ptr = match est {
        Some(est_ref) => &mut est_ref.0 as *mut byztime_stamp,
        None => std::ptr::null_mut(),
    };

    let max_ptr = match max {
        Some(max_ref) => &mut max_ref.0 as *mut byztime_stamp,
        None => std::ptr::null_mut(),
    };

    if unsafe { byztime_get_offset(ctx, min_ptr, est_ptr, max_ptr) } < 0 {
        Err(errno::errno().into())
    } else {
        Ok(())
    }
}

///Look up the current global time and error bounds and store them into the provided
///references.
fn global_time_assign(
    ctx: *mut byztime_ctx,
    min: Option<&mut Timestamp>,
    est: Option<&mut Timestamp>,
    max: Option<&mut Timestamp>,
) -> io::Result<()> {
    let min_ptr = match min {
        Some(min_ref) => &mut min_ref.0 as *mut byztime_stamp,
        None => std::ptr::null_mut(),
    };

    let est_ptr = match est {
        Some(est_ref) => &mut est_ref.0 as *mut byztime_stamp,
        None => std::ptr::null_mut(),
    };

    let max_ptr = match max {
        Some(max_ref) => &mut max_ref.0 as *mut byztime_stamp,
        None => std::ptr::null_mut(),
    };

    if unsafe { byztime_get_global_time(ctx, min_ptr, est_ptr, max_ptr) } < 0 {
        Err(errno::errno().into())
    } else {
        Ok(())
    }
}

/// Interface to common functionality of `ConsumerContext` and `ProviderContext`
pub trait Context: Sized {
    /// Return a raw pointer to the underlying [byztime_sys::byztime_ctx].
    fn as_mut_ptr(&self) -> *mut byztime_ctx;

    /// Close the timedata file. Calling this function rather than
    /// simply dropping the `Context` object allows graceful handling
    /// of disk failures or other I/O errors that emerge while
    /// closing the file. (The `Drop` instance handles such errors by
    /// panicking).
    fn close(self) -> io::Result<()>;

    /// Look up the current estimated offset (global clock - local
    /// clock) and error bounds and return it as `(min, est, max)`.
    fn offset(&self) -> io::Result<(Timestamp, Timestamp, Timestamp)> {
        let mut min = Timestamp::default();
        let mut est = Timestamp::default();
        let mut max = Timestamp::default();

        offset_assign(
            self.as_mut_ptr(),
            Some(&mut min),
            Some(&mut est),
            Some(&mut max),
        )?;
        Ok((min, est, max))
    }

    /// Look up the current global time and error bounds and return them as `(min, est, max)`.
    ///
    /// It is important to be aware that `min` and `max` are bounds on the
    /// *actual* global time, not on other nodes' estimation thereof. It
    /// is guranteed that other correct nodes' ranges will overlap ours,
    /// that is, their `min` will be less than our `max`, and their `max`
    /// will be greater than our `min`. However, it is *not* guaranteed
    /// that other correct nodes' `est` will be between our `min` and our
    /// `max`.
    fn global_time(&self) -> io::Result<(Timestamp, Timestamp, Timestamp)> {
        let mut min = Timestamp::default();
        let mut est = Timestamp::default();
        let mut max = Timestamp::default();

        global_time_assign(
            self.as_mut_ptr(),
            Some(&mut min),
            Some(&mut est),
            Some(&mut max),
        )?;
        Ok((min, est, max))
    }

    /// Return the drift rate, in parts per billion, that [offset](Self::offset)
    /// and [global_time](Self::global_time) use in their error bound calculations.
    fn get_drift(&self) -> i64 {
        unsafe { byztime_get_drift(self.as_mut_ptr()) }
    }

    /// Set the drift rate, in parts per billion, for [offset](Self::offset) and
    /// [global_time](Self::global_time) to use in their error bound calculations.
    fn set_drift(&self, drift_ppb: i64) {
        unsafe { byztime_set_drift(self.as_mut_ptr(), drift_ppb) }
    }

    /** Begin slewing time estimates.

    This function changes how `est` is calcuated in future calls to
    [offset](Self::offset) and [global_time](Self::global_time). When a context is first opened, time
    estimation is in "step" mode where the estimate is always the
    midpoint of the min and max. Such an estimate changes discontinuously
    every time a new data point is obtained, and can move backward.

    Calling this function causes future estimates to be clamped such
    that they will be more consistent with each other. Specifically,
    if [global_time](Self::global_time) returns an estimate of *g*₁ at
    local time *l*₁  and an estimate of *g*₂ at local time *l*₂, then *g*₂
    will be clamped such that
    `min_rate_ppb` ≤ 10⁹ ⋅ (*g*₂ - *g*₁)/(*l*₂ - *l*₁) ≤ `max_rate_ppb`.

    It is unwise to enter slew mode until the clock is known to be at
    least reasonably accurate: otherwise it may take a very long time
    to catch up with a large future correction. For this reason, this
    function accepts a `maxerror` parameter which will cause it to
    return an error and remain in step mode if (`max`-`min`)/2 ≥ `max_error`.

    Calling this function while already in slew mode is equivalent to
    switching to step mode and then immediately back into slew mode:
    it will cause the estimate to catch up to the current midpoint by
    a one-time step.

    A maximum rate of `i64::MAX` is treated as infinity. A call such as
    `slew(0, i64::MAX, max_error)` will allow the estimate to advance at
    arbitrarily high or low speed but never to move backward.

    When in slew mode, it becomes possible to obtain `(min,est,max)` tuples
    such that `est < min` or `est > max`. This can happen a previous
    estimate with wide error bounds is superceded by a new estimate
    with narrower ones which do not include the previous estimate. */
    fn slew(
        &self,
        min_rate_ppb: i64,
        max_rate_ppb: i64,
        max_error: Option<Timestamp>,
    ) -> io::Result<()> {
        let ret = unsafe {
            byztime_slew(
                self.as_mut_ptr(),
                min_rate_ppb,
                max_rate_ppb,
                match max_error {
                    Some(e) => &e.0 as *const byztime_stamp,
                    None => std::ptr::null() as *const byztime_stamp,
                },
            )
        };
        if ret < 0 {
            Err(errno::errno().into())
        } else {
            Ok(())
        }
    }

    /// Go back into step mode following a previous call to [slew](Self::slew).
    fn step(&self) -> io::Result<()> {
        let ret = unsafe { byztime_step(self.as_mut_ptr()) };
        if ret < 0 {
            Err(errno::errno().into())
        } else {
            Ok(())
        }
    }
}

///Provides a read-only interface to a timedata file
pub struct ConsumerContext {
    ctx: *mut byztime_ctx,
}

unsafe impl Send for ConsumerContext {}
unsafe impl Sync for ConsumerContext {}

impl ConsumerContext {
    ///Open a timedata file for read-only access
    pub fn open(path: &path::Path) -> io::Result<ConsumerContext> {
        let path_vec = Vec::from(path.as_os_str().as_bytes());
        let path_cstring =
            CString::new(path_vec).map_err(|_| io::Error::from(errno::Errno(libc::ENOENT)))?;
        let ctx = unsafe { byztime_open_ro(path_cstring.as_ptr() as *const i8) };

        if ctx.is_null() {
            Err(errno::errno().into())
        } else {
            Ok(ConsumerContext { ctx })
        }
    }
}

impl Context for ConsumerContext {
    fn as_mut_ptr(&self) -> *mut byztime_ctx {
        self.ctx
    }

    fn close(mut self) -> io::Result<()> {
        let ctx = self.as_mut_ptr();
        let ret = unsafe { byztime_close(ctx) };
        self.ctx = std::ptr::null_mut();
        if ret < 0 {
            Err(errno::errno().into())
        } else {
            Ok(())
        }
    }
}

impl Drop for ConsumerContext {
    fn drop(&mut self) {
        if self.as_mut_ptr() != std::ptr::null_mut() && unsafe { byztime_close(self.ctx) } < 0 {
            panic!("byztime_close: {}", errno::errno());
        }
    }
}

///Provides a read-write interface to a timedata file
pub struct ProviderContext {
    ctx: *mut byztime_ctx,
}

unsafe impl Send for ProviderContext {}
unsafe impl Sync for ProviderContext {}

impl ProviderContext {
    ///Opens a timedata file for read-write access.
    pub fn open(path: &path::Path) -> io::Result<ProviderContext> {
        let path_str = path.to_str().ok_or(errno::Errno(libc::ENOENT))?;
        let path_cstr = CString::new(path_str).map_err(|_| errno::Errno(libc::ENOENT))?;
        let ctx = unsafe { byztime_open_rw(path_cstr.as_ptr() as *const i8) };
        if ctx.is_null() {
            Err(errno::errno().into())
        } else {
            Ok(ProviderContext { ctx })
        }
    }

    ///Updates the offset and error bounds in the timedata file.
    pub fn set_offset(
        &self,
        offset: Timestamp,
        error: Timestamp,
        as_of: Timestamp,
    ) -> io::Result<()> {
        let offset_ptr = &offset.0 as *const byztime_stamp;
        let error_ptr = &error.0 as *const byztime_stamp;
        let asof_ptr = &as_of.0 as *const byztime_stamp;
        if unsafe { byztime_set_offset(self.ctx, offset_ptr, error_ptr, asof_ptr) } < 0 {
            Err(errno::errno().into())
        } else {
            Ok(())
        }
    }

    fn offset_quick_assign(&self, offset: &mut Timestamp) {
        let offset_ptr = &mut offset.0 as *mut byztime_stamp;
        unsafe {
            byztime_get_offset_quick(self.ctx, offset_ptr);
        }
    }

    /// Returns the `offset` that was stored by the last call to [set_offset](Self::set_offset).
    pub fn offset_quick(&self) -> Timestamp {
        let mut offset = Timestamp::default();
        self.offset_quick_assign(&mut offset);
        offset
    }

    fn offset_raw_assign(
        &self,
        offset: &mut Timestamp,
        error: &mut Timestamp,
        as_of: &mut Timestamp,
    ) {
        let offset_ptr = &mut offset.0 as *mut byztime_stamp;
        let error_ptr = &mut error.0 as *mut byztime_stamp;
        let as_of_ptr = &mut as_of.0 as *mut byztime_stamp;
        unsafe {
            byztime_get_offset_raw(self.ctx, offset_ptr, error_ptr, as_of_ptr);
        }
    }

    ///Returns the `(offset, error, as_of)` tuple that was stored by the last call to [set_offset](Self::set_offset).
    pub fn offset_raw(&self) -> (Timestamp, Timestamp, Timestamp) {
        let mut offset = Timestamp::default();
        let mut error = Timestamp::default();
        let mut as_of = Timestamp::default();
        self.offset_raw_assign(&mut offset, &mut error, &mut as_of);
        (offset, error, as_of)
    }

    ///Updates the real offset (POSIX time - global time) in the timedata file.
    pub fn update_real_offset(&self) -> io::Result<()> {
        let ret = unsafe { byztime_update_real_offset(self.ctx) };
        if ret < 0 {
            Err(errno::errno().into())
        } else {
            Ok(())
        }
    }
}

impl Context for ProviderContext {
    fn as_mut_ptr(&self) -> *mut byztime_ctx {
        self.ctx
    }

    fn close(mut self) -> io::Result<()> {
        let ctx = self.as_mut_ptr();
        let ret = unsafe { byztime_close(ctx) };
        self.ctx = std::ptr::null_mut();
        if ret < 0 {
            Err(errno::errno().into())
        } else {
            Ok(())
        }
    }
}

impl Drop for ProviderContext {
    fn drop(&mut self) {
        if self.as_mut_ptr() != std::ptr::null_mut() && unsafe { byztime_close(self.ctx) } < 0 {
            panic!("byztime_close: {}", errno::errno());
        }
    }
}

#[cfg(any(test, feature = "with_quickcheck"))]
impl Arbitrary for Timestamp {
    fn arbitrary<G: Gen>(g: &mut G) -> Timestamp {
        Timestamp::new(g.gen(), g.gen_range(0, 1_000_000_000))
    }
}

#[cfg(any(test, feature = "with_quickcheck"))]
impl Arbitrary for Era {
    fn arbitrary<G: Gen>(g: &mut G) -> Era {
        Era(g.gen())
    }
}

/** Install a signal handler for graceful recovery from page faults in the
timedata file.

 If the timedata file gets truncated after it has been opened,
 future accesses to it will raise `SIGBUS`. This function installs a
 signal handler that will allow whatever function was trying to
 access the truncated file to gracefully error out with `EPROTO`
 rather than crashing the program. If the `SIGBUS` was caused for some
 reason unrelated to a timedata access, this handler will reraise `SIGBUS`
 with the kernel default signal handler, which will cause the program to
 crash and dump core just as it normally would.

 A timedata file getting truncated while open is not something that
 should ever ordinarily happen; it would indicate that the byztime
 daemon or some or other process that has write permissions to the
 file is buggy or malicious. Benign mistakes such as the user
 specifying a path that does not point to a valid timedata file are
 detected and handled without relying on `SIGBUS`. Nonetheless,
 this crate is designed such that even a malicious byztime server
 should not ever be able to cause a client to crash or hang, and it
 is necessary to be able to trap and recover from `SIGBUS` in order
 to uphold that guarantee.

 Calling this function will replace whatever `SIGBUS` handler was
 previously installed, so use it only if nothing else in your
 program needs to handle `SIGBUS`. Otherwise, call
 [byztime_sys::byztime_handle_sigbus] (no safe wrapper
provided) from within your custom signal handler.*/
pub fn install_sigbus_handler() -> io::Result<()> {
    if unsafe { byztime_install_sigbus_handler(std::ptr::null_mut()) } < 0 {
        Err(errno::errno().into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn equality_is_reflexive(t: Timestamp) -> bool {
        t == t
    }

    fn denormalize<G: Gen>(g: &mut G, t: Timestamp) -> Timestamp {
        loop {
            let delta_s = g.gen_range(
                i64::min_value() / 1_000_000_000,
                i64::max_value() / 1_000_000_000,
            );
            let neg_delta_ns = delta_s * 1_000_000_000;
            match (
                t.seconds().checked_add(delta_s),
                t.nanoseconds().checked_sub(neg_delta_ns),
            ) {
                (Some(s), Some(ns)) => return Timestamp::new(s, ns),
                _ => (),
            }
        }
    }

    struct TestDenormal {
        t: Timestamp,
    }
    impl Testable for TestDenormal {
        fn result<G: Gen>(&self, g: &mut G) -> TestResult {
            let x = denormalize(g, self.t);
            let y = denormalize(g, self.t);
            TestResult::from_bool(x == y)
        }
    }

    #[quickcheck]
    fn equality_of_denormals(t: Timestamp) -> TestDenormal {
        TestDenormal { t }
    }

    #[quickcheck]
    fn t_plus_zero_is_t(t: Timestamp) -> bool {
        t + Timestamp::default() == t
    }

    #[test]
    fn half_plus_half_is_one() {
        let x = Timestamp::new(0, 500_000_000);
        let y = x + x;
        assert_eq!(y.seconds(), 1);
        assert_eq!(y.nanoseconds(), 0);
    }

    #[test]
    #[should_panic]
    fn addition_panics_on_overflow() {
        let _ = Timestamp::max_value() + Timestamp::max_value();
    }

    #[quickcheck]
    fn addition_is_associative(a: Timestamp, b: Timestamp, c: Timestamp) -> bool {
        a.wrapping_add(b.wrapping_add(c)) == a.wrapping_add(b).wrapping_add(c)
    }

    #[quickcheck]
    fn addition_is_commutative(a: Timestamp, b: Timestamp) -> bool {
        a.wrapping_add(b) == b.wrapping_add(a)
    }

    #[quickcheck]
    fn subtraction_is_negated_addition(a: Timestamp, b: Timestamp) -> bool {
        a.wrapping_sub(b) == a.wrapping_add(Timestamp::default().wrapping_sub(b))
    }

    #[quickcheck]
    fn scale_one(t: Timestamp) -> bool {
        t.scale(1_000_000_000) == t
    }

    #[quickcheck]
    fn scale_zero(t: Timestamp) -> bool {
        t.scale(0) == Timestamp::default()
    }

    #[quickcheck]
    fn scale_two(t: Timestamp) -> bool {
        t.wrapping_scale(2_000_000_000) == t.wrapping_add(t)
    }

    #[quickcheck]
    fn scale_half(t: Timestamp) -> bool {
        t.scale(500_000_000) == t.halve()
    }

    #[quickcheck]
    fn scale_neg_one(t: Timestamp) -> bool {
        t.wrapping_scale(-1_000_000_000) == Timestamp::default().wrapping_sub(t)
    }

    #[quickcheck]
    fn add_cmp(a: Timestamp, b: Timestamp) -> TestResult {
        match a.checked_add(b) {
            Some(c) => TestResult::from_bool(
                (b > Timestamp::default()) && c > a
                    || (b < Timestamp::default()) && c < a
                    || (b == Timestamp::default()) && c == a,
            ),
            None => TestResult::discard(),
        }
    }

    #[test]
    fn local_time_succeeds() {
        Timestamp::local_time().expect("Failed to query local time");
    }

    #[test]
    fn real_time_succeeds() {
        Timestamp::real_time().expect("Failed to query real time");
    }
}
