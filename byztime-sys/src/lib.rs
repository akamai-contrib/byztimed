// Copyright 2021, Akamai Technologies, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::os::raw;

#[repr(C)]
pub struct byztime_ctx {
    _unused: [u8; 0],
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct byztime_stamp {
    pub seconds: i64,
    pub nanoseconds: i64,
}

extern "C" {
    pub fn byztime_stamp_normalize(stamp: *mut byztime_stamp) -> raw::c_int;
    pub fn byztime_stamp_add(
        sum: *mut byztime_stamp,
        stamp1: *const byztime_stamp,
        stamp2: *const byztime_stamp,
    ) -> raw::c_int;
    pub fn byztime_stamp_sub(
        diff: *mut byztime_stamp,
        stamp1: *const byztime_stamp,
        stamp2: *const byztime_stamp,
    ) -> raw::c_int;
    pub fn byztime_stamp_scale(
        prod: *mut byztime_stamp,
        stamp: *const byztime_stamp,
        ppb: i64,
    ) -> raw::c_int;
    pub fn byztime_stamp_halve(prod: *mut byztime_stamp, stamp: *const byztime_stamp);
    pub fn byztime_stamp_cmp(
        stamp1: *const byztime_stamp,
        stamp2: *const byztime_stamp,
    ) -> raw::c_int;
    pub fn byztime_open_ro(pathname: *const raw::c_char) -> *mut byztime_ctx;
    pub fn byztime_get_offset(
        ctx: *mut byztime_ctx,
        min: *mut byztime_stamp,
        est: *mut byztime_stamp,
        max: *mut byztime_stamp,
    ) -> raw::c_int;
    pub fn byztime_get_global_time(
        ctx: *mut byztime_ctx,
        min: *mut byztime_stamp,
        est: *mut byztime_stamp,
        max: *mut byztime_stamp,
    ) -> raw::c_int;
    pub fn byztime_set_drift(ctx: *mut byztime_ctx, drift_ppb: i64);
    pub fn byztime_get_drift(ctx: *const byztime_ctx) -> i64;
    pub fn byztime_slew(
        ctx: *mut byztime_ctx,
        min_rate_ppb: i64,
        max_rate_ppb: i64,
        maxerror: *const byztime_stamp,
    ) -> raw::c_int;
    pub fn byztime_step(ctx: *mut byztime_ctx) -> raw::c_int;
    pub fn byztime_open_rw(pathname: *const raw::c_char) -> *mut byztime_ctx;
    pub fn byztime_set_offset(
        ctx: *mut byztime_ctx,
        offset: *const byztime_stamp,
        error: *const byztime_stamp,
        as_of: *const byztime_stamp,
    ) -> raw::c_int;
    pub fn byztime_get_offset_quick(ctx: *const byztime_ctx, offset: *mut byztime_stamp);
    pub fn byztime_get_offset_raw(
        ctx: *const byztime_ctx,
        offset: *mut byztime_stamp,
        error: *mut byztime_stamp,
        as_of: *mut byztime_stamp,
    );
    pub fn byztime_update_real_offset(ctx: *mut byztime_ctx) -> raw::c_int;
    pub fn byztime_get_clock_era(era: *mut raw::c_uchar) -> raw::c_int;
    pub fn byztime_get_local_time(local_time: *mut byztime_stamp) -> raw::c_int;
    pub fn byztime_get_real_time(real_time: *mut byztime_stamp) -> raw::c_int;
    pub fn byztime_close(ctx: *mut byztime_ctx) -> raw::c_int;
    pub fn byztime_install_sigbus_handler(oact: *mut libc::sigaction) -> raw::c_int;
    pub fn byztime_handle_sigbus(
        signo: raw::c_int,
        info: *mut libc::siginfo_t,
        context: *mut raw::c_void,
    );
}
