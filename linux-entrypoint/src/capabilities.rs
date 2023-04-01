#![allow(non_camel_case_types)]

use crate::error::{errno, reset_errno};
use core::ffi::c_void;
use libc::c_int;

// From linux/uapi/capability.h
type cap_t = *mut c_void;
type cap_value_t = u32;

const CAP_SETPCAP: cap_value_t = 8;

#[repr(C)]
enum cap_flag_t {
    CAP_EFFECTIVE = 0,
    CAP_PERMITTED = 1,
}

#[repr(C)]
#[derive(PartialEq, Eq)]
enum cap_flag_value_t {
    CAP_CLEAR = 0,
    CAP_SET = 1,
}

#[link(name = "cap")]
extern "C" {
    fn cap_get_proc() -> cap_t;
    fn cap_set_proc(cap: cap_t) -> c_int;
    fn cap_clear(cap: cap_t) -> c_int;
    fn cap_get_flag(
        cap_p: cap_t,
        cap: cap_value_t,
        flag: cap_flag_t,
        value_p: *mut cap_flag_value_t,
    ) -> c_int;
    fn cap_set_flag(
        cap_p: cap_t,
        flag: cap_flag_t,
        ncap: c_int,
        caps: *const cap_value_t,
        value: cap_flag_value_t,
    ) -> c_int;
    fn cap_drop_bound(cap: cap_value_t) -> c_int;
    fn cap_free(obj: *const c_void);
}

pub(crate) fn drop_capabilities() {
    reset_errno();
    let state = unsafe { cap_get_proc() };
    if state.is_null() {
        log_nonfatal!("cap_get_proc() failed with code {}", errno());
        return;
    }

    let mut holding_setpcap = cap_flag_value_t::CAP_CLEAR;
    let res = unsafe {
        cap_get_flag(
            state,
            CAP_SETPCAP,
            cap_flag_t::CAP_PERMITTED,
            &mut holding_setpcap as *mut _,
        )
    };
    if res != 0 {
        log_nonfatal!("cap_get_flag(CAP_SETPCAP) failed with code {}", errno());
    } else if holding_setpcap == cap_flag_value_t::CAP_SET {
        let cap_to_raise = CAP_SETPCAP;
        let res = unsafe {
            cap_set_flag(
                state,
                cap_flag_t::CAP_EFFECTIVE,
                1,
                &cap_to_raise as *const _,
                cap_flag_value_t::CAP_SET,
            )
        };
        if res != 0 {
            log_nonfatal!(
                "cap_set_flag(CAP_EFFECTIVE, CAP_SETPCAP, CAP_SET) failed with code {}",
                errno()
            );
        } else {
            let res = unsafe { cap_set_proc(state) };
            if res != 0 {
                log_nonfatal!(
                    "cap_set_proc(enabled CAP_SETPCAP) failed with code {}",
                    errno()
                );
            } else {
                for cap in 0.. {
                    reset_errno();
                    let res = unsafe { cap_drop_bound(cap as cap_value_t) };
                    if res != 0 {
                        break;
                    }
                }
            }
        }
    }

    // Clear our permitted, inherit, and effective sets.
    // Note that this also implicitly clears our ambient set.
    let res = unsafe { cap_clear(state) };
    if res != 0 {
        log_nonfatal!("cap_clear() failed with code {}", errno());
    } else {
        let res = unsafe { cap_set_proc(state) };
        if res != 0 {
            log_nonfatal!("cap_set_proc(cleared state) failed with code {}", errno());
        }
    }
    unsafe {
        cap_free(state);
    }
}
