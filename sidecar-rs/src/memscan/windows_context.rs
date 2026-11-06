//! Supported, short-lived thread-context capture. Never read a running
//! thread's context: acquire one suspension, read, and release exactly that
//! suspension before allocating, inspecting memory, or judging the result.
#![cfg_attr(not(windows), allow(dead_code))]

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT};
use windows_sys::Win32::System::Threading::{
    GetCurrentThreadId, GetProcessIdOfThread, GetThreadId, OpenThread, ResumeThread, SuspendThread,
    THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};

#[repr(C, align(16))]
pub(super) struct AlignedContext(pub(super) CONTEXT);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CaptureError {
    pub(super) stage: &'static str,
    pub(super) code: u32,
}

impl CaptureError {
    fn last(stage: &'static str) -> Self {
        // SAFETY: GetLastError reads the calling thread's error code.
        Self {
            stage,
            code: unsafe { GetLastError() },
        }
    }

    pub(super) fn summary(self) -> String {
        format!("{} (Win32 {})", self.stage, self.code)
    }
}

struct ThreadHandle(HANDLE);

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        // SAFETY: this guard owns a successfully opened handle.
        unsafe { CloseHandle(self.0) };
    }
}

struct Suspension {
    thread: HANDLE,
    held: bool,
}

impl Suspension {
    fn release(&mut self) -> Result<(), CaptureError> {
        // One decrement preserves a suspension already owned by a debugger
        // or another collector. Never resume repeatedly until the count is 0.
        // SAFETY: the handle outlives this guard and has SUSPEND_RESUME access.
        if unsafe { ResumeThread(self.thread) } == u32::MAX {
            return Err(CaptureError::last("resume"));
        }
        self.held = false;
        Ok(())
    }
}

impl Drop for Suspension {
    fn drop(&mut self) {
        if self.held {
            // Also release on an early return/unwind; if the explicit resume
            // failed, retry once. The failure is still reported to the caller.
            let _ = self.release();
        }
    }
}

/// Capture a context without retaining a suspension beyond this call. Do not
/// return a context when capture OR resumption failed. Nothing in the suspended
/// interval allocates, takes Rust locks, or reads the target's memory.
fn capture(thread: HANDLE, flags: u32) -> Result<AlignedContext, CaptureError> {
    // GetThreadContext on the caller is invalid, and suspending it deadlocks.
    // SAFETY: queries on a handle with QUERY_LIMITED_INFORMATION access.
    let tid = unsafe { GetThreadId(thread) };
    if tid == 0 {
        return Err(CaptureError::last("thread identity"));
    }
    if tid == unsafe { GetCurrentThreadId() } {
        return Err(CaptureError {
            stage: "current thread skipped",
            code: 0,
        });
    }
    // SAFETY: CONTEXT is plain data; its alignment is enforced by the wrapper.
    let mut context: AlignedContext = unsafe { core::mem::zeroed() };
    context.0.ContextFlags = flags;
    if unsafe { SuspendThread(thread) } == u32::MAX {
        return Err(CaptureError::last("suspend"));
    }
    let mut suspension = Suspension { thread, held: true };
    // Save the error before ResumeThread can replace it. No heap operations or
    // formatting occur until our suspension has been released.
    let ok = unsafe { GetThreadContext(thread, &mut context.0) } != 0;
    let read_error = (!ok).then(|| CaptureError::last("get context"));
    suspension.release()?;
    if let Some(e) = read_error {
        return Err(e);
    }
    if context.0.ContextFlags & flags != flags {
        return Err(CaptureError {
            stage: "incomplete context",
            code: 0,
        });
    }
    Ok(context)
}

pub(super) fn read(tid: u32, pid: u32, flags: u32) -> Result<AlignedContext, CaptureError> {
    // SAFETY: the handle is owned below; only query/context/suspend rights are
    // requested. No SET_CONTEXT or process-write access is requested.
    let h = unsafe {
        OpenThread(
            THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME,
            0,
            tid,
        )
    };
    if h.is_null() {
        return Err(CaptureError::last("open context thread"));
    }
    let thread = ThreadHandle(h);
    // A thread ID from an earlier enumeration may have been reused. Never
    // suspend a thread belonging to a different process.
    let owner = unsafe { GetProcessIdOfThread(thread.0) };
    if owner == 0 {
        return Err(CaptureError::last("thread owner"));
    }
    if owner != pid {
        return Err(CaptureError {
            stage: "thread owner changed",
            code: 0,
        });
    }
    capture(thread.0, flags)
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "x86")))]
mod tests {
    use super::*;
    use core::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::{
        CreateThread, GetCurrentProcessId, Sleep, WaitForSingleObject, CREATE_SUSPENDED,
    };

    #[cfg(target_arch = "x86_64")]
    const FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64;
    #[cfg(target_arch = "x86")]
    const FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_X86;

    #[derive(Default)]
    struct State {
        stop: AtomicBool,
        ticks: AtomicUsize,
    }

    unsafe extern "system" fn worker(data: *mut c_void) -> u32 {
        // SAFETY: Worker owns this allocation until the thread exits.
        let state = unsafe { &*(data as *const State) };
        while !state.stop.load(Ordering::Acquire) {
            state.ticks.fetch_add(1, Ordering::Release);
            unsafe { Sleep(1) };
        }
        0
    }

    struct Worker {
        thread: ThreadHandle,
        tid: u32,
        state: Option<Box<State>>,
    }

    impl Worker {
        fn new(suspended: bool) -> Self {
            let mut state = Box::<State>::default();
            let mut tid = 0;
            // SAFETY: the boxed state stays at this address for the thread's lifetime.
            let h = unsafe {
                CreateThread(
                    core::ptr::null(),
                    0,
                    Some(worker),
                    (&mut *state as *mut State).cast(),
                    if suspended { CREATE_SUSPENDED } else { 0 },
                    &mut tid,
                )
            };
            assert!(!h.is_null());
            Self {
                thread: ThreadHandle(h),
                tid,
                state: Some(state),
            }
        }

        fn ticks(&self) -> usize {
            self.state.as_ref().unwrap().ticks.load(Ordering::Acquire)
        }

        fn advances_from(&self, before: usize) {
            let until = Instant::now() + Duration::from_secs(5);
            while self.ticks() <= before && Instant::now() < until {
                unsafe { Sleep(1) };
            }
            assert!(self.ticks() > before, "capture left the worker suspended");
        }

        fn suspend_count(&self) -> u32 {
            // Independent observation; undo this test's added suspension.
            let before = unsafe { SuspendThread(self.thread.0) };
            assert_ne!(before, u32::MAX);
            assert_ne!(unsafe { ResumeThread(self.thread.0) }, u32::MAX);
            before
        }
    }

    impl Drop for Worker {
        fn drop(&mut self) {
            self.state
                .as_ref()
                .unwrap()
                .stop
                .store(true, Ordering::Release);
            // Test-only cleanup of our dedicated worker, even after a failing
            // assertion. Never apply this drain to a production target.
            for _ in 0..8 {
                if unsafe { ResumeThread(self.thread.0) } <= 1 {
                    break;
                }
            }
            if unsafe { WaitForSingleObject(self.thread.0, 5000) } != WAIT_OBJECT_0 {
                // A failing test must not free memory a stuck worker still uses.
                let _ = Box::leak(self.state.take().unwrap());
            }
        }
    }

    #[test]
    fn captures_running_thread_and_always_releases_its_suspension() {
        let w = Worker::new(false);
        w.advances_from(0);
        for _ in 0..16 {
            let c = read(w.tid, unsafe { GetCurrentProcessId() }, FLAGS).expect("capture");
            assert_eq!(c.0.ContextFlags & FLAGS, FLAGS);
        }
        assert_eq!(w.suspend_count(), 0);
        w.advances_from(w.ticks());
        eprintln!("lrng-selftest: thread context: running worker resumed after 16 captures");
    }

    #[test]
    fn preserves_preexisting_suspension() {
        let w = Worker::new(true);
        read(w.tid, unsafe { GetCurrentProcessId() }, FLAGS).expect("capture suspended thread");
        assert_eq!(
            w.suspend_count(),
            1,
            "must preserve the creator's suspension"
        );
        assert_eq!(w.ticks(), 0);
        assert_eq!(unsafe { ResumeThread(w.thread.0) }, 1);
        w.advances_from(0);
    }

    #[test]
    fn failed_get_context_still_resumes_running_and_suspended_threads() {
        for suspended in [false, true] {
            let w = Worker::new(suspended);
            // Deliberately omit GET_CONTEXT while allowing suspension.
            let h = unsafe {
                OpenThread(
                    THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME,
                    0,
                    w.tid,
                )
            };
            assert!(!h.is_null());
            let h = ThreadHandle(h);
            let error = capture(h.0, FLAGS).err().expect("context access must fail");
            assert_eq!(error.stage, "get context");
            assert_eq!(w.suspend_count(), u32::from(suspended));
            if suspended {
                assert_eq!(unsafe { ResumeThread(w.thread.0) }, 1);
            }
            w.advances_from(w.ticks());
        }
    }

    #[test]
    fn denied_suspend_and_wrong_owner_do_not_capture() {
        let w = Worker::new(false);
        let h = unsafe {
            OpenThread(
                THREAD_QUERY_LIMITED_INFORMATION | THREAD_GET_CONTEXT,
                0,
                w.tid,
            )
        };
        assert!(!h.is_null());
        let h = ThreadHandle(h);
        assert_eq!(
            capture(h.0, FLAGS).err().expect("no suspend right").stage,
            "suspend"
        );
        assert_eq!(
            read(w.tid, 0, FLAGS).err().expect("wrong process").stage,
            "thread owner changed"
        );
        assert_eq!(w.suspend_count(), 0);
        w.advances_from(w.ticks());
    }

    #[test]
    fn skips_calling_thread_and_releases_on_unwind() {
        let error = read(
            unsafe { GetCurrentThreadId() },
            unsafe { GetCurrentProcessId() },
            FLAGS,
        )
        .err()
        .expect("caller must never be suspended");
        assert_eq!(error.stage, "current thread skipped");
        let w = Worker::new(false);
        let result = std::panic::catch_unwind(|| {
            assert_ne!(unsafe { SuspendThread(w.thread.0) }, u32::MAX);
            let _held = Suspension {
                thread: w.thread.0,
                held: true,
            };
            panic!("exercise suspension cleanup");
        });
        assert!(result.is_err());
        assert_eq!(w.suspend_count(), 0);
        w.advances_from(w.ticks());
    }
}
