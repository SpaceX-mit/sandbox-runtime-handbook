//! Non-interactive desktop for the sandbox child.
//!
//! Creates a per-exec named desktop on the **caller's current window
//! station** and exposes the `<winsta>\<desk>` path that
//! `STARTUPINFOW.lpDesktop` consumes. The sandbox child spawns onto
//! this desktop and so cannot enumerate or message top-level windows
//! on the interactive `WinSta0\Default`.
//!
//! Desktop-only — no `CreateWindowStationW`. Creating a new window
//! station requires create rights on the session's
//! `\Windows\WindowStations` object directory, which a non-elevated
//! token does not have on a standard interactive session
//! (`CreateWindowStationW → ACCESS_DENIED`, verified by probe).
//! `CreateDesktopW` on the **current** station works non-elevated, and
//! a separate desktop already provides the isolation that matters: a
//! window's message queue is per-desktop, so processes on different
//! desktops cannot `SendMessage`/enumerate each other (the shatter
//! threat). The clipboard- and atom-table separation a separate
//! station would add is already covered by the Job's UI limits
//! (`JOB_OBJECT_UILIMIT_READCLIPBOARD | WRITECLIPBOARD | GLOBALATOMS`).
//!
//! The kernel reference-counts a desktop by attached threads/handles.
//! The caller keeps the [`IsolatedDesk`] handle open from creation
//! until after the child exits — dropping it then releases the
//! kernel object.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CreateDesktopW, GetProcessWindowStation, GetThreadDesktop,
    GetUserObjectInformationW, DESKTOP_CONTROL_FLAGS, HDESK, UOI_NAME,
};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

use crate::util::wstr;

// winuser.h: DESKTOP_ALL_ACCESS = 0x1FF. OR with
// STANDARD_RIGHTS_REQUIRED so the creator holds full control on the
// object it just made.
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F_0000;
const DESK_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | 0x0000_01FF;

/// RAII holder for a per-exec desktop on the caller's current window
/// station, plus the wide `<winsta>\<desk>` buffer that backs
/// `STARTUPINFOW.lpDesktop`.
pub struct IsolatedDesk {
    desktop: HDESK,
    /// `STARTUPINFOW.lpDesktop` is `PWSTR` (mutable wide pointer per
    /// the API contract), so we keep the buffer here and hand out a
    /// raw pointer via [`desktop_name_ptr`]. Null-terminated.
    desk_path: Vec<u16>,
}

impl IsolatedDesk {
    /// Create a fresh per-exec desktop on the **current** window
    /// station — no `SetProcessWindowStation` dance. Default DACL
    /// (creator owns it; the only caller is `run_lockdown`, where the
    /// child shares the caller's user SID).
    ///
    /// Name = `srt-sb-<pid>-<rand32>` (random suffix so concurrent
    /// execs in the same process — e.g. tests — don't collide; the
    /// kernel-assigned name is read back for the `lpDesktop` path).
    pub fn new() -> Result<Self> {
        // Current station name (for the `<winsta>\<desk>` path). The
        // child's `lpDesktop` carries this name verbatim, so if the
        // read failed a guessed `WinSta0` would point the child at a
        // station the runner may not even be on — propagate.
        let ws_name = current_winsta_name()
            .context("read caller's window-station name")?;

        // pid + 32 random bits (system CSPRNG). The random suffix
        // is what makes concurrent same-process callers (e.g. test
        // threads) collision-free, so don't quietly fall back to a
        // zero suffix on RNG failure — surface it. `BCryptGenRandom`
        // with `USE_SYSTEM_PREFERRED_RNG` essentially never fails.
        let mut r = [0u8; 4];
        unsafe {
            BCryptGenRandom(None, &mut r, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
        }
        .ok()
        .context("BCryptGenRandom (desktop name suffix)")?;
        let req = format!(
            "srt-sb-{}-{:08x}",
            std::process::id(),
            u32::from_le_bytes(r),
        );
        let req_w = wstr(&req);

        let desktop = unsafe {
            CreateDesktopW(
                PCWSTR(req_w.as_ptr()),
                PCWSTR::null(),
                None,
                DESKTOP_CONTROL_FLAGS(0),
                DESK_ALL_ACCESS,
                None,
            )
        }
        .with_context(|| format!("CreateDesktopW({req}) on {ws_name}"))?;

        // Read back the actual assigned name.
        let desk_name = match object_name(HANDLE(desktop.0)) {
            Ok(n) => n,
            Err(e) => {
                unsafe {
                    let _ = CloseDesktop(desktop);
                }
                return Err(e.context("UOI_NAME on new desktop"));
            }
        };

        let desk_path = wstr(&format!("{ws_name}\\{desk_name}"));
        Ok(Self { desktop, desk_path })
    }

    /// Pointer to the wide name buffer for `STARTUPINFOW.lpDesktop`.
    /// Caller must keep `self` alive until after
    /// `CreateProcessAsUserW` returns.
    pub fn desktop_name_ptr(&mut self) -> *mut u16 {
        self.desk_path.as_mut_ptr()
    }
}

impl Drop for IsolatedDesk {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseDesktop(self.desktop);
        }
    }
}

/// Name of the window station this process is attached to (e.g.
/// `WinSta0`, `Service-0x0-<logonid>$`).
pub fn current_winsta_name() -> Result<String> {
    let ws = unsafe { GetProcessWindowStation() }
        .context("GetProcessWindowStation")?;
    if ws.0.is_null() {
        return Err(anyhow!("GetProcessWindowStation returned null"));
    }
    object_name(HANDLE(ws.0))
}

/// Name of this thread's current desktop (e.g. `Default`,
/// `srt-sb-…`). `None` on failure.
pub fn current_desktop_name() -> Option<String> {
    let d = unsafe { GetThreadDesktop(GetCurrentThreadId()) }.ok()?;
    if d.0.is_null() {
        return None;
    }
    object_name(HANDLE(d.0)).ok()
}

/// `true` when this thread is on the interactive `Default` desktop.
///
/// `run_lockdown` only creates a fresh [`IsolatedDesk`] when this
/// returns `true` — both the same-user broker and the two-hop runner
/// land on `WinSta0\Default` (the runner via `CreateProcessWithLogonW`
/// with `lpDesktop = NULL`, where seclogon grants the new logon
/// access to `WinSta0` including `WINSTA_CREATEDESKTOP`), so in
/// practice this is always `true` and each creates its own
/// `WinSta0\srt-sb-…` for its child. The check is the safety: a
/// caller already off `Default` (services, nested) inherits instead.
/// Name-based — a non-`Default` custom desktop is assumed isolated.
/// Any read failure → `true` (the safe default — try to create).
pub fn on_default_desktop() -> bool {
    current_desktop_name()
        .map(|n| n.eq_ignore_ascii_case("Default"))
        .unwrap_or(true)
}

/// Read a user-object's `UOI_NAME` (returned as a wide
/// NUL-terminated string).
fn object_name(h: HANDLE) -> Result<String> {
    let mut needed = 0u32;
    // Sizing call — expected to fail with ERROR_INSUFFICIENT_BUFFER
    // and write the required byte count.
    unsafe {
        let _ = GetUserObjectInformationW(
            h, UOI_NAME, None, 0, Some(&mut needed),
        );
    }
    if needed == 0 {
        return Err(anyhow!(
            "GetUserObjectInformationW sizing returned 0"
        ));
    }
    let mut buf = vec![0u8; needed as usize];
    unsafe {
        GetUserObjectInformationW(
            h,
            UOI_NAME,
            Some(buf.as_mut_ptr() as *mut c_void),
            needed,
            Some(&mut needed),
        )
        .context("GetUserObjectInformationW(UOI_NAME)")?;
    }
    // SAFETY: `buf` is `needed` bytes, even-length (UTF-16);
    // reinterpret as u16.
    let wide = unsafe {
        std::slice::from_raw_parts(
            buf.as_ptr() as *const u16,
            (needed as usize) / 2,
        )
    };
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    Ok(String::from_utf16_lossy(&wide[..end]))
}
