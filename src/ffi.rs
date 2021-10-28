// Copyright 2021 Jason Ish
//
// MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;

use crate::{FlowbitCommand, NewRule};
use crate::{Flowbits, RuleOption};

#[repr(C)]
pub struct CRule {
    pub action: *const c_char,
    pub proto: *const c_char,
    pub option_count: usize,

    // An array of CRuleOptions which are safe to read from C.
    pub options: *const CRuleOption,

    // The actual option data is stored here.
    pub __options: *const c_void,
}

#[repr(C)]
pub enum COptionType {
    Unknown,
    ByteJump,
    Metadata,
    Reference,
    Offset,
    Flowbits,
}

impl From<&RuleOption> for COptionType {
    fn from(o: &RuleOption) -> Self {
        match o {
            RuleOption::ByteJump(_) => Self::ByteJump,
            RuleOption::Metadata(_) => Self::Metadata,
            RuleOption::Reference(_) => Self::Reference,
            RuleOption::Offset(_) => Self::Offset,
            RuleOption::Flowbits(_) => Self::Flowbits,
            _ => panic!("unknown option"),
        }
    }
}

#[repr(C)]
pub struct CRuleOption {
    pub option_type: COptionType,
    pub option: *const c_void,
}

#[repr(C)]
pub struct CFlowbits {
    pub command: FlowbitCommand,
    pub size: usize,
    pub names: *const *const c_char,
    pub __names: *const c_void,
}

impl From<&Flowbits> for CFlowbits {
    fn from(f: &Flowbits) -> Self {
        // First create an array of CStrings as our backing store.
        let names: Vec<CString> = f
            .names
            .iter()
            .map(|n| CString::new(n.to_string()).unwrap())
            .collect();
        // Now create an array of c_char * type strings.
        let cnames: Vec<*const c_char> = names.iter().map(|n| n.as_ptr()).collect();
        let cflowbits = Self {
            command: f.command.clone(),
            size: names.len(),
            names: cnames.as_ptr() as *const *const c_char,
            __names: names.as_ptr() as *const c_void,
        };
        // Forget about the 2 arrays, they'll be remembered in the Drop impl.
        std::mem::forget(cnames);
        std::mem::forget(names);
        cflowbits
    }
}

impl Drop for CFlowbits {
    fn drop(&mut self) {
        unsafe {
            Vec::from_raw_parts(self.__names as *mut CString, self.size, self.size);
            Vec::from_raw_parts(self.names as *mut *const c_char, self.size, self.size);
        }
    }
}

/// # Safety
///
/// This function is unsafe as it has to convert a C string to a Rust string, so should only be
/// called with valid C (nul terminated) strings.
#[no_mangle]
pub unsafe extern "C" fn parse_rule(input: *const c_char) -> *mut CRule {
    let input = CStr::from_ptr(input).to_str().unwrap();
    let (_, rule) = crate::parse_rule(input).unwrap();
    let rule: NewRule = rule.into();

    let mut options = rule.options;
    options.shrink_to_fit();
    let mut coptions = Vec::with_capacity(options.len());
    for option in &options {
        match option {
            RuleOption::ByteJump(byte_jump) => {
                let coption = CRuleOption {
                    option_type: option.into(),
                    option: byte_jump as *const _ as *mut c_void,
                };
                coptions.push(coption);
            }
            // All options that are just a string can be handled here.
            RuleOption::Metadata(string) | RuleOption::Reference(string) => {
                let coption = CRuleOption {
                    option_type: option.into(),
                    option: CString::new(string.to_string()).unwrap().into_raw() as *const c_void,
                };
                coptions.push(coption);
            }
            RuleOption::Offset(u) => {
                let coption = CRuleOption {
                    option_type: option.into(),
                    option: Box::into_raw(Box::new(*u)) as *const c_void,
                };
                coptions.push(coption);
            }
            RuleOption::Flowbits(flowbits) => {
                dbg!(flowbits);
                let coption = CRuleOption {
                    option_type: option.into(),
                    option: Box::into_raw(Box::new(CFlowbits::from(flowbits))) as *const c_void,
                };
                coptions.push(coption);
            }
            _ => {
                let coption = CRuleOption {
                    option_type: COptionType::Unknown,
                    option: std::ptr::null(),
                };
                coptions.push(coption);
            }
        }
    }

    let crule = CRule {
        action: CString::new(rule.action).unwrap().into_raw(),
        proto: CString::new(rule.proto).unwrap().into_raw(),
        option_count: options.len(),
        options: coptions.as_ptr(),
        __options: options.as_ptr() as *const c_void,
    };
    std::mem::forget(options);
    std::mem::forget(coptions);
    Box::into_raw(Box::new(crule))
}

/// # Safety
///
/// As this function dereferences raw pointers it is unsafe. It should only be used to free a
/// `CRule` object return ed from `parse_rule`.
#[no_mangle]
pub unsafe extern "C" fn rule_free(rule: *mut CRule) {
    std::mem::drop(Box::from_raw(rule));
}

/// Drop implementation for CRule.
///
/// Just resume ownership of everything that was forgotten.
impl Drop for CRule {
    fn drop(&mut self) {
        unsafe {
            Vec::from_raw_parts(
                self.__options as *mut RuleOption,
                self.option_count,
                self.option_count,
            );
            Vec::from_raw_parts(
                self.options as *mut CRuleOption,
                self.option_count,
                self.option_count,
            );
            CString::from_raw(self.action as *mut c_char);
            CString::from_raw(self.proto as *mut c_char);
        }
    }
}

/// Drop implementation for CRuleOption.
///
/// For Rust options that are repr(C) no special drop handling is required. However, other
/// options probably had to allocate and forget data before passing the CRuleOption to C.
impl Drop for CRuleOption {
    fn drop(&mut self) {
        unsafe {
            match self.option_type {
                // Options that are just a string.
                COptionType::Metadata | COptionType::Reference => {
                    CString::from_raw(self.option as *mut c_char);
                }
                // Options that are just a u64.
                COptionType::Offset => {
                    Box::from_raw(self.option as *mut u64);
                }
                COptionType::Flowbits => {
                    Box::from_raw(self.option as *mut CFlowbits);
                }
                _ => {}
            }
        }
    }
}
