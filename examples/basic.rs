use once_cell::sync::Lazy;
use sharedbumper::SharedBumpAllocator;
use std::{
    alloc::{GlobalAlloc, Layout},
    collections::HashMap,
};

static STATE: Lazy<SharedBumpAllocator> = Lazy::new(|| SharedBumpAllocator::new("test.psm", 4096, std::ptr::null_mut()));

pub struct GlobalSharedBumpAllocator;

unsafe impl GlobalAlloc for GlobalSharedBumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        STATE.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        STATE.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: GlobalSharedBumpAllocator = GlobalSharedBumpAllocator;

fn main() {
    let mut map = HashMap::new();
    map.insert(0, "zero".to_string());
    let entry = map.remove(&0);
    assert_eq!(entry, Some("zero".to_string()));
}
