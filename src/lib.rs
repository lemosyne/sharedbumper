use sba::{sba_alloc, sba_dealloc, sba_drop, sba_metadata, sba_new, Sba};
use std::alloc::{GlobalAlloc, Layout};

pub struct SharedBumpAllocator(Sba);

impl SharedBumpAllocator {
    pub fn new(path: &str, capacity: usize) -> Self {
        let mut cpath = [0; 4096];
        let path_len = path.as_bytes().len();

        if path_len >= cpath.len() {
            panic!("shmem_file path too long");
        }

        cpath[..path_len].copy_from_slice(path.as_bytes());
        cpath[path_len] = 0;

        Self(unsafe { sba_new(cpath.as_ptr() as *mut _, capacity) })
    }

    pub fn metadata(&self) -> *mut u8 {
        unsafe { sba_metadata(&self.0 as *const _ as *mut _) }
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
