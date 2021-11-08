// Copyright 2021 Open Information Security Foundation
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

use crate::Flowbits;
use crate::{Element, FlowbitCommand};

#[repr(u16)]
pub enum ElementTag {
    Action,
    Protocol,
    SrcAddr,
    SrcPort,
    Direction,
    DstAddr,
    DstPort,
    ByteJump,
    Classtype,
    Content,
    Depth,
    Dsize,
    Distance,
    EndsWith,
    FastPattern,
    FileData,
    Flow,
    Flowbits,
    FtpBounce,
    IsDataAt,
    Message,
    Metadata,
    NoAlert,
    NoCase,
    Offset,
    Pcre,
    RawBytes,
    Reference,
    Rev,
    Sid,
    StartsWith,
    Within,
    GenericOption,
}

// This is more or less here to make sure ElementTag stays in sync with Element.
impl From<&Element> for ElementTag {
    fn from(e: &Element) -> ElementTag {
        match e {
            // Header elements.
            Element::Action(_) => Self::Action,
            Element::Protocol(_) => Self::Protocol,
            Element::SrcAddr(_) => Self::SrcAddr,
            Element::SrcPort(_) => Self::SrcPort,
            Element::Direction(_) => Self::Direction,
            Element::DstAddr(_) => Self::DstAddr,
            Element::DstPort(_) => Self::DstPort,

            // Option elements in alphabetical order.
            Element::Flowbits(_) => Self::Flowbits,

            _ => unimplemented!(),
        }
    }
}

#[repr(C)]
pub struct CElement {
    pub tag: ElementTag,
    pub val: *const c_void,
}

impl Drop for CElement {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                ElementTag::Action => {
                    CString::from_raw(self.val as *mut c_char);
                }
                ElementTag::Flowbits => {
                    Box::from_raw(self.val as *mut CFlowbits);
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug)]
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
        dbg!(&cflowbits);
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
/// It's FFI!
#[no_mangle]
pub unsafe extern "C" fn srp_parse_elements(
    input: *const c_char,
    size: *mut usize,
) -> *const CElement {
    let input = CStr::from_ptr(input).to_str().unwrap();
    let (_, elements) = crate::parse_elements(input).unwrap();
    let (_, elements) = crate::reduce_elements(elements).unwrap();

    // Now convert the elements to C style structs.
    let mut celements = Vec::new();
    for element in &elements {
        match element {
            Element::Action(action) => {
                let ce = CElement {
                    tag: element.into(),
                    val: CString::new(action.to_string()).unwrap().into_raw() as *const c_void,
                };
                celements.push(ce);
            }
            Element::Flowbits(flowbits) => {
                let tag: ElementTag = element.into();
                let cf: CFlowbits = flowbits.into();
                let ce = CElement {
                    tag,
                    val: Box::into_raw(Box::new(cf)) as *const c_void,
                };
                celements.push(ce);
            }
            _ => {}
        }
    }
    celements.shrink_to_fit();
    *size = celements.len();
    let r = celements.as_ptr() as *const CElement;
    std::mem::forget(celements);
    r
}

/// # Safety
///
/// It's FFI!
#[no_mangle]
pub unsafe extern "C" fn srp_free_elements(elements: *const CElement, size: usize) {
    let _elements = Vec::from_raw_parts(elements as *mut CElement, size, size);
}
