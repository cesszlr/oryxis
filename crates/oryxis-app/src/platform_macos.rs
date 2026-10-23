//! macOS platform-specific window and view behavior adjustments.
//!
//! When running on macOS with native window decorations and a full-size
//! content view (`titlebar_transparent` + `fullsize_content_view`), AppKit
//! treats non-opaque views residing within the title bar region as draggable
//! window background space by querying `-[NSView mouseDownCanMoveWindow]`.
//!
//! Because `WinitView` defaults to returning `YES`, clicking and dragging
//! any interactive element placed in the top bar (such as tabs) causes AppKit
//! to unintentionally drag the entire `NSWindow`.
//!
//! This module overrides `mouseDownCanMoveWindow` on `NSView` / `WinitView`
//! to return `NO` (`false`), thereby preventing AppKit's automatic window
//! dragging on view interaction. Explicit window dragging from title bar
//! spacers, gutters, and handles continues to work via Oryxis's custom
//! `TabsMessage::WindowDrag` -> `iced::window::drag(id)` pipeline.

#[cfg(target_os = "macos")]
pub(crate) fn disable_view_window_dragging() {
    unsafe extern "C" {
        fn objc_getClass(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
        fn sel_registerName(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
        fn class_getInstanceMethod(
            cls: *mut std::ffi::c_void,
            name: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;
        fn method_setImplementation(
            m: *mut std::ffi::c_void,
            imp: unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> bool,
        ) -> *mut std::ffi::c_void;
        fn class_addMethod(
            cls: *mut std::ffi::c_void,
            name: *mut std::ffi::c_void,
            imp: unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> bool,
            types: *const std::ffi::c_char,
        ) -> bool;
    }

    unsafe extern "C" fn mouse_down_can_move_window(
        _this: *mut std::ffi::c_void,
        _cmd: *mut std::ffi::c_void,
    ) -> bool {
        false
    }

    unsafe {
        let sel = sel_registerName(c"mouseDownCanMoveWindow".as_ptr());
        if sel.is_null() {
            return;
        }

        // Hook on NSView so all current and future views (including WinitView)
        // return false for automatic window dragging.
        let nsview_cls = objc_getClass(c"NSView".as_ptr());
        if !nsview_cls.is_null() {
            let method = class_getInstanceMethod(nsview_cls, sel);
            if !method.is_null() {
                method_setImplementation(method, mouse_down_can_move_window);
            } else {
                class_addMethod(nsview_cls, sel, mouse_down_can_move_window, c"c@:".as_ptr());
            }
        }

        // Also add directly to WinitView if it has already been registered.
        let winit_view_cls = objc_getClass(c"WinitView".as_ptr());
        if !winit_view_cls.is_null() {
            class_addMethod(winit_view_cls, sel, mouse_down_can_move_window, c"c@:".as_ptr());
        }
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
    fn test_disable_view_window_dragging() {
        disable_view_window_dragging();
    }
}
