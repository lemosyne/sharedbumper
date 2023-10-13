use sba::*;
use std::{alloc::{GlobalAlloc, Layout}, sync::atomic::AtomicUsize};

pub struct SharedBumpAllocator(SbaLocal);

impl SharedBumpAllocator {
    pub fn new(path: &str, capacity: usize, base_addr_req: *mut ()) -> Self {
        let mut cpath = [0; 4096];
        let path_len = path.as_bytes().len();

        if path_len >= cpath.len() {
            panic!("path too long: {path}");
        }

        cpath[..path_len].copy_from_slice(path.as_bytes());
        cpath[path_len] = 0;

        Self(unsafe { sba_new(cpath.as_ptr() as *mut _, capacity, base_addr_req as *mut _) })
    }

    pub fn metadata(&self) -> *mut *mut u8 {
        unsafe { sba_metadata(&self.0 as *const _ as *mut _) as *mut _ }
    }
}

unsafe impl GlobalAlloc for SharedBumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        sba_alloc(&self.0 as *const _ as *mut _, layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        sba_dealloc(&self.0 as *const _ as *mut _, ptr, layout.size())
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Attempt to extend the block naturally
        if sba_extend(&self.0 as *const _ as *mut _, ptr, layout.size(), new_size) {
            return ptr;
        }

        // Otherwise defer to the default implementation

        // SAFETY: the caller must ensure that the `new_size` does not overflow.
        // `layout.align()` comes from a `Layout` and is thus guaranteed to be valid.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: the caller must ensure that `new_layout` is greater than zero.
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            // SAFETY: the previously allocated block cannot overlap the newly allocated block.
            // The safety contract for `dealloc` must be upheld by the caller.
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, new_ptr, std::cmp::min(layout.size(), new_size));
                self.dealloc(ptr, layout);
            }
        }
        new_ptr
    }

}

impl Drop for SharedBumpAllocator {
    fn drop(&mut self) {
        unsafe { sba_drop(&mut self.0 as *mut _) }
    }
}

#[cfg(test)]
mod test {
    use std::ptr;

    use super::*;

    #[test]
    fn alloc_dealloc() {
        unsafe {
            let _ = std::fs::remove_file("/dev/shm/test.psm");
            let alloc = SharedBumpAllocator::new("test.psm", 0x10_000_000, ptr::null_mut());

            let mut ptrs = [ptr::null_mut(); 1000];
            let mut layouts = [Layout::new::<()>(); 1000];
            for i in 1..100 {
                layouts[i] = Layout::from_size_align(i * 0x117, 1).unwrap();
                ptrs[i] = alloc.alloc(layouts[i]);
                
                std::slice::from_raw_parts_mut(ptrs[i], layouts[i].size()).fill(b'A');
            }

            for i in (1..100).step_by(3) {
                alloc.dealloc(ptrs[i], layouts[i]);
            }

            for i in (1..50).rev() {
                ptrs[i] = alloc.alloc(layouts[i]);
                std::slice::from_raw_parts_mut(ptrs[i], layouts[i].size()).fill(b'B');
            }

            for i in 1..100 {
                alloc.dealloc(ptrs[i], layouts[i]);
            }
        }
    }
}
