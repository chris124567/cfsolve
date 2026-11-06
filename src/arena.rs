//! Keeps the deobfuscator's syntax tree contiguous in memory.
//!
//! Deobfuscation is a few hundred walks over one large tree, and walking it is bound by memory
//! latency: after hundreds of rewrites its nodes are scattered across the heap. So each round
//! starts from a copy of the tree ([`relayout`]). With the general allocator the copy is spread
//! over a page per size class; when the application installs [`Allocator`] as its global
//! allocator, the copy is bump-allocated into a chunk of its own instead, every node next to the
//! one walked before it. Deobfuscation then runs about 30% faster.
//!
//! Chunks come from one range of address space reserved on first use. Freeing anything in that
//! range does nothing; a chunk is handed back whole once the tree it holds has been dropped. Each
//! thread uses its own chunks, so solves can run side by side.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// The address space a chunk spans. A copy of the largest script's tree takes about 13 MB.
const CHUNK: usize = 256 << 20;
/// Chunks in the reserved range: two per thread deobfuscating at once.
const CHUNKS: usize = 64;

/// The application's allocator, with deobfuscation's tree copies kept contiguous.
///
/// ```ignore
/// #[global_allocator]
/// static ALLOCATOR: cfsolve::Allocator<std::alloc::System> = cfsolve::Allocator::new(std::alloc::System);
/// ```
pub struct Allocator<A> {
    inner: A,
}

impl<A> Allocator<A> {
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }
}

/// Whether [`Allocator`] is the global allocator: copies use chunks only then.
static INSTALLED: AtomicBool = AtomicBool::new(false);
/// The start of the reserved range, or zero before it is reserved.
static RANGE: AtomicUsize = AtomicUsize::new(0);
/// The chunks in use, one bit each.
static TAKEN: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Whether this thread is copying into its chunk.
    static COPYING: Cell<bool> = const { Cell::new(false) };
    /// This thread's chunk, plus one; zero for none.
    static HELD: Cell<usize> = const { Cell::new(0) };
    /// Bytes allocated from this thread's chunk.
    static USED: Cell<usize> = const { Cell::new(0) };
    /// Bytes of this thread's chunk committed (Windows commits pages explicitly).
    static COMMITTED: Cell<usize> = const { Cell::new(0) };
}

fn in_range(pointer: *mut u8) -> bool {
    let start = RANGE.load(Ordering::Relaxed);
    let address = pointer.addr();
    start != 0 && address >= start && address < start + CHUNK * CHUNKS
}

/// The chunk this thread is copying into, if it is.
fn chunk_start() -> Option<usize> {
    COPYING
        .get()
        .then(|| HELD.get().checked_sub(1))
        .flatten()
        .map(|chunk| RANGE.load(Ordering::Relaxed) + chunk * CHUNK)
}

/// Allocates `layout` from this thread's chunk, or `None` if it isn't copying or the chunk is
/// full.
fn bump(layout: Layout) -> Option<*mut u8> {
    let start = chunk_start()?;
    let used = USED.get();
    let at = (start + used).next_multiple_of(layout.align());
    let end = at - start + layout.size();
    if end > CHUNK || !os::commit(start, end) {
        return None;
    }
    USED.set(end);
    Some(std::ptr::with_exposed_provenance_mut(at))
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for Allocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !INSTALLED.load(Ordering::Relaxed) {
            INSTALLED.store(true, Ordering::Relaxed);
        }
        match bump(layout) {
            Some(pointer) => pointer,
            // SAFETY: the caller's layout is passed on unchanged.
            None => unsafe { self.inner.alloc(layout) },
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Chunks start out zeroed and are never reused before they are handed back.
        match bump(layout) {
            Some(pointer) => pointer,
            // SAFETY: the caller's layout is passed on unchanged.
            None => unsafe { self.inner.alloc_zeroed(layout) },
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if !in_range(pointer) {
            // SAFETY: memory outside the range came from the inner allocator.
            unsafe { self.inner.dealloc(pointer, layout) }
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if !in_range(pointer) {
            // SAFETY: memory outside the range came from the inner allocator.
            return unsafe { self.inner.realloc(pointer, layout, size) };
        }
        // SAFETY: the caller guarantees `size` forms a valid layout with the same alignment.
        let grown = unsafe { self.alloc(Layout::from_size_align_unchecked(size, layout.align())) };
        if !grown.is_null() {
            // SAFETY: both blocks are valid for the smaller of their sizes and don't overlap.
            unsafe { std::ptr::copy_nonoverlapping(pointer, grown, layout.size().min(size)) };
        }
        grown
    }
}

/// Replaces `value` with a copy of itself, laid out contiguously in a fresh chunk when
/// [`Allocator`] is installed. The chunk the old value was copied into is handed back once it
/// is dropped.
pub(crate) fn relayout<T: Clone>(value: &mut T) {
    let previous = HELD.replace(0);
    if let Some(chunk) = take_chunk() {
        HELD.set(chunk + 1);
        USED.set(0);
        COMMITTED.set(0);
        COPYING.set(true);
    }
    /// Stops copying into the chunk however the copy ends.
    struct Copying;
    impl Drop for Copying {
        fn drop(&mut self) {
            COPYING.set(false);
        }
    }
    let copy = {
        let _copying = Copying;
        value.clone()
    };
    *value = copy;
    if let Some(chunk) = previous.checked_sub(1) {
        hand_back(chunk);
    }
}

/// Hands back this thread's chunk. Call once the value [`relayout`] copied into it is dropped.
pub(crate) fn release() {
    if let Some(chunk) = HELD.replace(0).checked_sub(1) {
        hand_back(chunk);
    }
}

/// A free chunk for this thread, reserving the range first if needed. `None` without
/// [`Allocator`], when the range can't be reserved, or when every chunk is in use.
fn take_chunk() -> Option<usize> {
    if !INSTALLED.load(Ordering::Relaxed) {
        return None;
    }
    static RESERVED: OnceLock<Option<usize>> = OnceLock::new();
    let start = (*RESERVED.get_or_init(|| os::reserve(CHUNK * CHUNKS)))?;
    RANGE.store(start, Ordering::Relaxed);
    let mut taken = TAKEN.load(Ordering::Acquire);
    loop {
        let chunk = (!taken).trailing_zeros() as usize;
        if chunk >= CHUNKS {
            return None;
        }
        match TAKEN.compare_exchange_weak(
            taken,
            taken | 1 << chunk,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(chunk),
            Err(now) => taken = now,
        }
    }
}

fn hand_back(chunk: usize) {
    os::decommit(RANGE.load(Ordering::Relaxed) + chunk * CHUNK, CHUNK);
    TAKEN.fetch_and(!(1 << chunk), Ordering::AcqRel);
}

#[cfg(unix)]
mod os {
    /// Reserves `size` bytes of address space, committed lazily by the system as pages are
    /// touched.
    pub(super) fn reserve(size: usize) -> Option<usize> {
        // SAFETY: an anonymous private mapping at an address of the system's choosing.
        let start = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        (start != libc::MAP_FAILED).then(|| start.expose_provenance())
    }

    /// Pages are committed as they are touched.
    pub(super) fn commit(_: usize, _: usize) -> bool {
        true
    }

    /// Returns the memory of `size` bytes at `start` to the system, leaving the addresses
    /// reserved and zeroed.
    pub(super) fn decommit(start: usize, size: usize) {
        // SAFETY: remaps part of the range reserved above; nothing there is in use any more.
        unsafe {
            libc::mmap(
                std::ptr::with_exposed_provenance_mut(start),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_NORESERVE | libc::MAP_FIXED,
                -1,
                0,
            );
        }
    }
}

#[cfg(windows)]
mod os {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc,
        VirtualFree,
    };

    use super::COMMITTED;

    /// Pages are committed this many bytes at a time as a chunk fills.
    const STEP: usize = 4 << 20;

    pub(super) fn reserve(size: usize) -> Option<usize> {
        // SAFETY: reserves address space at an address of the system's choosing.
        let start = unsafe { VirtualAlloc(std::ptr::null(), size, MEM_RESERVE, PAGE_NOACCESS) };
        (!start.is_null()).then(|| start.expose_provenance())
    }

    /// Commits the chunk at `start` up to `end` bytes; `false` if the system refuses.
    pub(super) fn commit(start: usize, end: usize) -> bool {
        let committed = COMMITTED.get();
        if end <= committed {
            return true;
        }
        let size = (end - committed)
            .next_multiple_of(STEP)
            .min(super::CHUNK - committed);
        // SAFETY: commits reserved pages of this thread's chunk.
        let done = unsafe {
            VirtualAlloc(
                std::ptr::with_exposed_provenance(start + committed),
                size,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        if done.is_null() {
            return false;
        }
        COMMITTED.set(committed + size);
        true
    }

    pub(super) fn decommit(start: usize, size: usize) {
        // SAFETY: decommits part of the range reserved above; nothing there is in use any more.
        unsafe {
            VirtualFree(
                std::ptr::with_exposed_provenance_mut(start),
                size,
                MEM_DECOMMIT,
            )
        };
    }
}
