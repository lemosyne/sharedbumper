use once_cell::sync::Lazy;
use sharedbumper::SharedBumpAllocator;
use std::{alloc::GlobalAlloc, collections::HashMap};

static STATE: Lazy<SharedBumpAllocator> =
    Lazy::new(|| SharedBumpAllocator::new("test.psm", 1 << 24));

pub struct GlobalSharedBumpAllocator;

unsafe impl GlobalAlloc for GlobalSharedBumpAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        STATE.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        STATE.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: GlobalSharedBumpAllocator = GlobalSharedBumpAllocator;

fn main() {
    let mut map = HashMap::new();
    map.insert(0, "zero".to_string());
    map.remove(&0);
}
