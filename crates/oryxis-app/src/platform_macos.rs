//! macOS platform-specific window and view behavior adjustments.
//!
//! 1. **Window Dragging Suppression on Interactive Views:**
//!    When running on macOS with native window decorations and a full-size
//!    content view (`titlebar_transparent` + `fullsize_content_view`), AppKit
//!    treats non-opaque views residing within the title bar region as draggable
//!    window background space by querying `-[NSView mouseDownCanMoveWindow]`.
//!    Because `WinitView` defaults to returning `YES`, clicking and dragging
//!    any interactive element placed in the top bar (such as tabs) causes AppKit
//!    to unintentionally drag the entire `NSWindow`.
//!    This module overrides `mouseDownCanMoveWindow` on `NSView` / `WinitView`
//!    to return `NO` (`false`). Explicit window dragging from title bar spacers,
//!    gutters, and handles continues to work via Oryxis's custom
//!    `TabsMessage::WindowDrag` -> `iced::window::drag(id)` pipeline.
//!
//! 2. **Traffic Light Vertical Centering (`NSWindowToolbarStyleUnifiedCompact`):**
//!    Without an attached `NSToolbar`, AppKit gives a transparent full-size
//!    content window a 28-32 pt title bar and places the 14 pt traffic light
//!    buttons near the top edge (centered around y = 14-16 pt), which looks
//!    visibly off-center inside Oryxis's 40 pt top bar (`BAR_HEIGHT = 40.0`).
//!    Attaching an empty `NSToolbar` with `NSWindowToolbarStyleUnifiedCompact`
//!    (4) instructs AppKit to use a 40 pt title bar and vertically center the
//!    traffic light buttons at y = 20.0 pt (13 pt top and bottom margins).

#[cfg(target_os = "macos")]
use std::ffi::{c_char, c_void};
#[cfg(target_os = "macos")]
use std::sync::Once;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> *mut c_void;
    fn sel_registerName(name: *const c_char) -> *mut c_void;
    fn class_getInstanceMethod(cls: *mut c_void, name: *mut c_void) -> *mut c_void;
    fn method_setImplementation(m: *mut c_void, imp: *const c_void) -> *const c_void;
    fn class_addMethod(
        cls: *mut c_void,
        name: *mut c_void,
        imp: *const c_void,
        types: *const c_char,
    ) -> bool;
    fn objc_msgSend();
}

#[cfg(target_os = "macos")]
static INIT_HOOKS: Once = Once::new();

#[cfg(target_os = "macos")]
static ORIG_MAKE_KEY_AND_ORDER_FRONT: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "macos")]
static ORIG_ORDER_WINDOW: AtomicUsize = AtomicUsize::new(0);

/// `NSWindowStyleMaskFullSizeContentView` (1 << 15).
#[cfg(target_os = "macos")]
const NS_WINDOW_STYLE_MASK_FULL_SIZE_CONTENT_VIEW: usize = 1 << 15;

/// `NSWindowToolbarStyleUnifiedCompact` (4).
#[cfg(target_os = "macos")]
const NS_WINDOW_TOOLBAR_STYLE_UNIFIED_COMPACT: isize = 4;

#[cfg(target_os = "macos")]
unsafe extern "C" fn mouse_down_can_move_window(_this: *mut c_void, _cmd: *mut c_void) -> bool {
    false
}

/// Ensures that a full-size content `NSWindow` has an empty `NSToolbar` with
/// `NSWindowToolbarStyleUnifiedCompact` attached so AppKit expands the title
/// bar height to 40 pt and vertically centers the traffic light buttons.
#[cfg(target_os = "macos")]
pub(crate) unsafe fn ensure_unified_compact_toolbar(window: *mut c_void) {
    if window.is_null() {
        return;
    }

    type MsgSendResponds = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> bool;
    type MsgSendStyleMask = unsafe extern "C" fn(*mut c_void, *mut c_void) -> usize;
    type MsgSendId = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
    type MsgSendIdCharPtr =
        unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char) -> *mut c_void;
    type MsgSendIdId =
        unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
    type MsgSendVoidId = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
    type MsgSendVoidInt = unsafe extern "C" fn(*mut c_void, *mut c_void, isize);
    type MsgSendVoidBool = unsafe extern "C" fn(*mut c_void, *mut c_void, bool);
    type MsgSendVoid = unsafe extern "C" fn(*mut c_void, *mut c_void);

    unsafe {
        let msg_responds: MsgSendResponds =
            std::mem::transmute(objc_msgSend as *const c_void);
        let msg_style_mask: MsgSendStyleMask =
            std::mem::transmute(objc_msgSend as *const c_void);
        let msg_id: MsgSendId = std::mem::transmute(objc_msgSend as *const c_void);
        let msg_id_char: MsgSendIdCharPtr =
            std::mem::transmute(objc_msgSend as *const c_void);
        let msg_id_id: MsgSendIdId = std::mem::transmute(objc_msgSend as *const c_void);
        let msg_void_id: MsgSendVoidId = std::mem::transmute(objc_msgSend as *const c_void);
        let msg_void_int: MsgSendVoidInt = std::mem::transmute(objc_msgSend as *const c_void);
        let msg_void_bool: MsgSendVoidBool = std::mem::transmute(objc_msgSend as *const c_void);
        let msg_void: MsgSendVoid = std::mem::transmute(objc_msgSend as *const c_void);

        let sel_responds = sel_registerName(c"respondsToSelector:".as_ptr());
        let sel_style_mask = sel_registerName(c"styleMask".as_ptr());
        let sel_toolbar = sel_registerName(c"toolbar".as_ptr());
        let sel_set_toolbar = sel_registerName(c"setToolbar:".as_ptr());
        let sel_set_toolbar_style = sel_registerName(c"setToolbarStyle:".as_ptr());

        if !msg_responds(window, sel_responds, sel_style_mask)
            || !msg_responds(window, sel_responds, sel_toolbar)
            || !msg_responds(window, sel_responds, sel_set_toolbar)
        {
            return;
        }

        let style_mask = msg_style_mask(window, sel_style_mask);
        if (style_mask & NS_WINDOW_STYLE_MASK_FULL_SIZE_CONTENT_VIEW) == 0 {
            return;
        }

        let existing_toolbar = msg_id(window, sel_toolbar);
        if !existing_toolbar.is_null() {
            return;
        }

        let nstoolbar_cls = objc_getClass(c"NSToolbar".as_ptr());
        let nsstring_cls = objc_getClass(c"NSString".as_ptr());
        if nstoolbar_cls.is_null() || nsstring_cls.is_null() {
            return;
        }

        let sel_alloc = sel_registerName(c"alloc".as_ptr());
        let sel_init_utf8 = sel_registerName(c"initWithUTF8String:".as_ptr());
        let sel_init_id = sel_registerName(c"initWithIdentifier:".as_ptr());
        let sel_set_separator = sel_registerName(c"setShowsBaselineSeparator:".as_ptr());
        let sel_release = sel_registerName(c"release".as_ptr());

        let str_alloc = msg_id(nsstring_cls, sel_alloc);
        if str_alloc.is_null() {
            return;
        }
        let identifier = msg_id_char(str_alloc, sel_init_utf8, c"OryxisToolbar".as_ptr());
        if identifier.is_null() {
            return;
        }

        let toolbar_alloc = msg_id(nstoolbar_cls, sel_alloc);
        if toolbar_alloc.is_null() {
            msg_void(identifier, sel_release);
            return;
        }

        let toolbar = msg_id_id(toolbar_alloc, sel_init_id, identifier);
        msg_void(identifier, sel_release);
        if toolbar.is_null() {
            return;
        }

        if msg_responds(toolbar, sel_responds, sel_set_separator) {
            msg_void_bool(toolbar, sel_set_separator, false);
        }

        msg_void_id(window, sel_set_toolbar, toolbar);
        if msg_responds(window, sel_responds, sel_set_toolbar_style) {
            msg_void_int(
                window,
                sel_set_toolbar_style,
                NS_WINDOW_TOOLBAR_STYLE_UNIFIED_COMPACT,
            );
        }
        msg_void(toolbar, sel_release);
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn swizzled_make_key_and_order_front(
    this: *mut c_void,
    cmd: *mut c_void,
    sender: *mut c_void,
) {
    unsafe {
        ensure_unified_compact_toolbar(this);
        let orig_ptr = ORIG_MAKE_KEY_AND_ORDER_FRONT.load(Ordering::SeqCst);
        if orig_ptr != 0 {
            let orig: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) =
                std::mem::transmute(orig_ptr);
            orig(this, cmd, sender);
        }
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn swizzled_order_window(
    this: *mut c_void,
    cmd: *mut c_void,
    place: isize,
    relative_to: isize,
) {
    unsafe {
        ensure_unified_compact_toolbar(this);
        let orig_ptr = ORIG_ORDER_WINDOW.load(Ordering::SeqCst);
        if orig_ptr != 0 {
            let orig: unsafe extern "C" fn(*mut c_void, *mut c_void, isize, isize) =
                std::mem::transmute(orig_ptr);
            orig(this, cmd, place, relative_to);
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn disable_view_window_dragging() {
    unsafe {
        let sel = sel_registerName(c"mouseDownCanMoveWindow".as_ptr());
        if !sel.is_null() {
            let imp = mouse_down_can_move_window as *const c_void;

            // Hook on NSView so all current and future views (including WinitView)
            // return false for automatic window dragging.
            let nsview_cls = objc_getClass(c"NSView".as_ptr());
            if !nsview_cls.is_null() {
                let method = class_getInstanceMethod(nsview_cls, sel);
                if !method.is_null() {
                    method_setImplementation(method, imp);
                } else {
                    class_addMethod(nsview_cls, sel, imp, c"c@:".as_ptr());
                }
            }

            // Also add directly to WinitView if it has already been registered.
            let winit_view_cls = objc_getClass(c"WinitView".as_ptr());
            if !winit_view_cls.is_null() {
                class_addMethod(winit_view_cls, sel, imp, c"c@:".as_ptr());
            }
        }

        // Swizzle NSWindow ordering methods once to attach the unified compact
        // toolbar that centers the traffic light buttons in the 40 pt top bar.
        INIT_HOOKS.call_once(|| {
            let nswindow_cls = objc_getClass(c"NSWindow".as_ptr());
            if nswindow_cls.is_null() {
                return;
            }

            let sel_make_key = sel_registerName(c"makeKeyAndOrderFront:".as_ptr());
            if !sel_make_key.is_null() {
                let m = class_getInstanceMethod(nswindow_cls, sel_make_key);
                if !m.is_null() {
                    let prev = method_setImplementation(
                        m,
                        swizzled_make_key_and_order_front as *const c_void,
                    );
                    ORIG_MAKE_KEY_AND_ORDER_FRONT.store(prev as usize, Ordering::SeqCst);
                }
            }

            let sel_order_win = sel_registerName(c"orderWindow:relativeTo:".as_ptr());
            if !sel_order_win.is_null() {
                let m = class_getInstanceMethod(nswindow_cls, sel_order_win);
                if !m.is_null() {
                    let prev =
                        method_setImplementation(m, swizzled_order_window as *const c_void);
                    ORIG_ORDER_WINDOW.store(prev as usize, Ordering::SeqCst);
                }
            }
        });
    }
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub(crate) fn disable_view_window_dragging() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_disable_view_window_dragging_idempotent() {
        disable_view_window_dragging();
        disable_view_window_dragging();
        assert_ne!(ORIG_MAKE_KEY_AND_ORDER_FRONT.load(Ordering::SeqCst), 0);
        assert_ne!(ORIG_ORDER_WINDOW.load(Ordering::SeqCst), 0);
        unsafe {
            ensure_unified_compact_toolbar(std::ptr::null_mut());
        }
    }
}
