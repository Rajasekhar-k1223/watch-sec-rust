use windows::Win32::Foundation::HWND;
fn main() {
    let h: HWND = HWND(0);
    let is_null = h.0 != std::ptr::null_mut();
}
