//! Sıfırlayan global ayırıcı (CLI'de ölçüm sonrası).
//!
//! `dealloc` ve `realloc`'ta serbest bırakılan bölge `zeroize` (volatile) ile sıfırlanır, sonra
//! sistem ayırıcısına verilir. Kapsar: egui/winit olay metinleri (`Event::Text`), clap
//! kopyaları, yol dizgeleri gibi heap kalıntıları. Kapsamaz: yığın, yazmaçlar, çekirdek
//! tamponları, `mmap` ile doğrudan alınan bölgeler (onlar `LargeSecretBuf`'tadır).
//! Bedeli: her serbest bırakmada boyut kadar yazma.

use std::alloc::{GlobalAlloc, Layout, System};

use zeroize::Zeroize;

/// `System` üzerine sıfırlayan sarmalayıcı. `#[global_allocator] static A: ZeroizingAlloc =
/// ZeroizingAlloc;` ile kullanılır.
#[derive(Debug, Default, Clone, Copy)]
pub struct ZeroizingAlloc;

fn zero_region(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    // SAFETY: çağıran (`dealloc`/`realloc`), `ptr..ptr+size` aralığının bu ayırıcıdan alınmış,
    // hâlâ geçerli ve başka referansı olmayan bir bölge olduğunu garanti eder.
    let s = unsafe { core::slice::from_raw_parts_mut(ptr, size) };
    s.zeroize();
}

// SAFETY: tüm yöntemler `System`'e devreder; `dealloc` öncesi sıfırlama yalnızca serbest
// bırakılacak bölgeye yazar; `realloc` yeni blok ayırır, kopyalar, eskiyi sıfırlayıp bırakır —
// GlobalAlloc sözleşmesi (hizalama, boyut, null dönüşü) korunur.
unsafe impl GlobalAlloc for ZeroizingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` çağıranın geçerli (sıfır olmayan boyutlu) düzenidir.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: yukarıdaki gibi.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        zero_region(ptr, layout.size());
        // SAFETY: `ptr` bu ayırıcıdan `layout` ile alındı (çağıran sözleşmesi).
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return core::ptr::null_mut();
        };
        // SAFETY: `new_layout` geçerli ve sıfır olmayan boyutlu (GlobalAlloc::realloc sözleşmesi).
        let new_ptr = unsafe { System.alloc(new_layout) };
        if new_ptr.is_null() {
            return new_ptr;
        }
        let n = layout.size().min(new_size);
        // SAFETY: `ptr` en az `layout.size()`, `new_ptr` en az `new_size` bayt geçerli; bloklar
        // farklı ayırmalardan geldiği için örtüşmez.
        unsafe { core::ptr::copy_nonoverlapping(ptr, new_ptr, n) };
        // SAFETY: `ptr`/`layout` çağıranın geçerli eski bloğu; artık kullanılmayacak.
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
        // SAFETY: geçerli, sıfır olmayan boyutlu düzen.
        let first = unsafe { alloc.alloc(small) };
        assert!(!first.is_null());
        // SAFETY: `first` 64 baytlık, bu testin tek sahip olduğu blok.
        let bytes = unsafe { core::slice::from_raw_parts_mut(first, 64) };
        for (i, b) in (0u8..).zip(bytes.iter_mut()) {
            *b = i;
        }
        // SAFETY: `first`/`small` bu ayırıcıdan; yeni boyut sıfır değil.
        let grown = unsafe { alloc.realloc(first, small, 256) };
        assert!(!grown.is_null());
        assert_eq!(grown as usize % 16, 0, "hiza korunmalı");
        // SAFETY: `grown` en az 256 baytlık geçerli blok; ilk 64 bayt kopyalandı.
        let kept = unsafe { core::slice::from_raw_parts(grown, 64) };
        assert!((0u8..).zip(kept.iter()).all(|(i, b)| *b == i));
        // SAFETY: `grown`/`big` bu ayırıcıdan.
        unsafe { alloc.dealloc(grown, big) };
        // SAFETY: geçerli düzen.
        let zeroed = unsafe { alloc.alloc_zeroed(small) };
        // SAFETY: `zeroed` 64 baytlık sıfırlanmış blok.
        let view = unsafe { core::slice::from_raw_parts(zeroed, 64) };
        assert!(view.iter().all(|b| *b == 0));
        // SAFETY: `zeroed`/`small` bu ayırıcıdan.
        unsafe { alloc.dealloc(zeroed, small) };
    }
}
