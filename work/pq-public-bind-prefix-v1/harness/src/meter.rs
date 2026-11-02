use std::{alloc::{GlobalAlloc,Layout,System},sync::atomic::{AtomicBool,AtomicUsize,Ordering::SeqCst}};
struct Counter;static ACTIVE:AtomicBool=AtomicBool::new(false);static ALLOCS:AtomicUsize=AtomicUsize::new(0);static BYTES:AtomicUsize=AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counter{
 unsafe fn alloc(&self,l:Layout)->*mut u8{if ACTIVE.load(SeqCst){ALLOCS.fetch_add(1,SeqCst);BYTES.fetch_add(l.size(),SeqCst);}unsafe{System.alloc(l)}}
 unsafe fn alloc_zeroed(&self,l:Layout)->*mut u8{if ACTIVE.load(SeqCst){ALLOCS.fetch_add(1,SeqCst);BYTES.fetch_add(l.size(),SeqCst);}unsafe{System.alloc_zeroed(l)}}
 unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}
 unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8{if ACTIVE.load(SeqCst){ALLOCS.fetch_add(1,SeqCst);BYTES.fetch_add(n,SeqCst);}unsafe{System.realloc(p,l,n)}}
}
#[global_allocator]static ALLOC:Counter=Counter;
pub fn measured<T>(f:impl FnOnce()->T)->(T,usize,usize){ALLOCS.store(0,SeqCst);BYTES.store(0,SeqCst);ACTIVE.store(true,SeqCst);let x=f();ACTIVE.store(false,SeqCst);(x,ALLOCS.load(SeqCst),BYTES.load(SeqCst))}
