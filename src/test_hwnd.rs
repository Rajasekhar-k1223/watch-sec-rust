use windows::Win32::Foundation::{HWND, MAX_PATH};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId};

fn main() {
    unsafe {
        let hwnd: HWND = GetForegroundWindow();
        println!("HWND: {:?}", hwnd);
        if hwnd.0 != std::ptr::null_mut() {
            let mut title_buf = [0u16; 512];
            let len = GetWindowTextW(hwnd, &mut title_buf);
            if len > 0 {
                let title = String::from_utf16_lossy(&title_buf[..len as usize]);
                println!("Title: {}", title);
            } else {
                println!("Title is empty, len: {}", len);
            }
        }
    }
}
