use sba::{sba_alloc, sba_dealloc, sba_drop, sba_new, Sba};
use std::{
    alloc::{GlobalAlloc, Layout},
    ffi::CString,
};

pub struct SharedBumpAllocator(Sba);

impl SharedBumpAllocator {
    pub fn new(path: &str, capacity: usize) -> Self {
        let path = CString::new(path).unwrap();
        Self(unsafe { sba_new(path.as_ptr(), capacity) })
    }
}

unsafe impl GlobalAlloc for SharedBumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        sba_alloc(&self.0 as *const _ as *mut _, layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        sba_dealloc(&self.0 as *const _ as *mut _, ptr, layout.size())
    }
}

impl Drop for SharedBumpAllocator {
    fn drop(&mut self) {
        unsafe { sba_drop(&mut self.0 as *mut _) }
    }
}
