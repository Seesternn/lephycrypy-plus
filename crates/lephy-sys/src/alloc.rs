//! Zeroizing global allocator (measured for the CLI).
//!
//! On `dealloc` and `realloc` the freed region is zeroized with `zeroize` (volatile) and then
//! handed to the system allocator. Covers heap residue such as egui/winit event text
//! (`Event::Text`), clap copies and path strings. Does not cover the stack, registers, kernel
//! buffers or regions taken directly with `mmap` (those are in `LargeSecretBuf`).
//! Cost: one write per freed byte.

use std::alloc::{GlobalAlloc, Layout, System};

use zeroize::Zeroize;

/// Zeroizing wrapper around `System`. Used with `#[global_allocator] static A: ZeroizingAlloc =
/// ZeroizingAlloc;`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ZeroizingAlloc;

fn zero_region(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    // SAFETY: the caller (`dealloc`/`realloc`) guarantees that `ptr..ptr+size` is a region from
    // this allocator that is still valid and has no other references.
    let s = unsafe { core::slice::from_raw_parts_mut(ptr, size) };
    s.zeroize();
}

// SAFETY: every method delegates to `System`; zeroizing before `dealloc` writes only to the
// region being freed; `realloc` allocates a new block, copies, zeroizes and frees the old one —
// the GlobalAlloc contract (alignment, size, null return) is kept.
unsafe impl GlobalAlloc for ZeroizingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is the caller's valid (non-zero-sized) layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        zero_region(ptr, layout.size());
        // SAFETY: `ptr` came from this allocator with `layout` (caller contract).
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return core::ptr::null_mut();
        };
        // SAFETY: `new_layout` is valid and non-zero-sized (GlobalAlloc::realloc contract).
        let new_ptr = unsafe { System.alloc(new_layout) };
        if new_ptr.is_null() {
            return new_ptr;
        }
        let n = layout.size().min(new_size);
        // SAFETY: `ptr` is valid for at least `layout.size()`, `new_ptr` for at least `new_size`
        // bytes; the blocks come from different allocations and do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(ptr, new_ptr, n) };
        // SAFETY: `ptr`/`layout` are the caller's valid old block; it is no longer used.
        unsafe { self.dealloc(ptr, layout) };
        new_ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_realloc_dealloc_roundtrip() {
        let alloc = ZeroizingAlloc;
        let small = Layout::from_size_align(64, 16).unwrap_or(Layout::new::<u8>());
        let big = Layout::from_size_align(256, 16).unwrap_or(small);
        // SAFETY: valid, non-zero-sized layout.
        let first = unsafe { alloc.alloc(small) };
        assert!(!first.is_null());
        // SAFETY: `first` is a 64-byte block owned only by this test.
        let bytes = unsafe { core::slice::from_raw_parts_mut(first, 64) };
        for (i, b) in (0u8..).zip(bytes.iter_mut()) {
            *b = i;
        }
        // SAFETY: `first`/`small` are from this allocator; the new size is non-zero.
        let grown = unsafe { alloc.realloc(first, small, 256) };
        assert!(!grown.is_null());
        assert_eq!(grown as usize % 16, 0, "alignment must be kept");
        // SAFETY: `grown` is a valid block of at least 256 bytes; the first 64 were copied.
        let kept = unsafe { core::slice::from_raw_parts(grown, 64) };
        assert!((0u8..).zip(kept.iter()).all(|(i, b)| *b == i));
        // SAFETY: `grown`/`big` are from this allocator.
        unsafe { alloc.dealloc(grown, big) };
        // SAFETY: valid layout.
        let zeroed = unsafe { alloc.alloc_zeroed(small) };
        // SAFETY: `zeroed` is a zeroed 64-byte block.
        let view = unsafe { core::slice::from_raw_parts(zeroed, 64) };
        assert!(view.iter().all(|b| *b == 0));
        // SAFETY: `zeroed`/`small` are from this allocator.
        unsafe { alloc.dealloc(zeroed, small) };
    }
}
