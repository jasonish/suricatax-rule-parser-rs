// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! FFI for the rule parser.
//!
//! Experimental: This may never get finished and may better live
//! directly in Suricata should Suricata if ever use this crate.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub struct CRule {
    _inner: crate::Rule,
}

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

fn set_last_error(msg: &str) -> *const c_char {
    let msg = CString::new(msg).unwrap();
    LAST_ERROR.with(|le| {
        *le.borrow_mut() = msg.clone();
        le.borrow().as_ptr()
    })
}

#[no_mangle]
pub unsafe extern "C" fn scx_parse_rule(
    buf: *const c_char,
    errmsg: *mut *const c_char,
) -> *mut CRule {
    let buf = match CStr::from_ptr(buf).to_str() {
        Ok(buf) => buf,
        Err(err) => {
            if !errmsg.is_null() {
                *errmsg = set_last_error(&format!("{:?}", err));
            }
            return std::ptr::null_mut();
        }
    };
    match crate::parse_rule(buf) {
        Ok(rule) => {
            let rule = Box::new(CRule { _inner: rule });
            Box::into_raw(rule)
        }
        Err(err) => {
            if !errmsg.is_null() {
                *errmsg = set_last_error(&format!("{:?}", err));
            }
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_rule() {
        unsafe {
            let mut err_msg: *const c_char = std::ptr::null_mut();

            let input =
                CString::new("alert tcp any any -> any any (msg:\"test\"; sid:1;)").unwrap();
            let rule = scx_parse_rule(input.as_ptr(), &mut err_msg);
            assert!(!rule.is_null());

            let input =
                CString::new("alert tcp any any => any any (msg:\"test\"; sid:1;)").unwrap();
            let rule = scx_parse_rule(input.as_ptr(), &mut err_msg);
            let err_msg = std::ffi::CStr::from_ptr(err_msg).to_str().unwrap();
            assert!(rule.is_null());
            assert!(err_msg.contains("direction"));
        }
    }
}
