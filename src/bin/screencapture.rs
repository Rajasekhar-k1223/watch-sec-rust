#[cfg(windows)]
use windows::Win32::Graphics::Gdi::*;
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::*;
#[cfg(windows)]
use image::ImageBuffer;

#[cfg(windows)]
fn main() {
    unsafe {
        let hwnd = GetDesktopWindow();
        let hdc_screen = GetDC(hwnd);
        let hdc_mem = CreateCompatibleDC(hdc_screen);

        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);

        let hbm = CreateCompatibleBitmap(hdc_screen, width, height);
        let h_old = SelectObject(hdc_mem, hbm);

        // Copy screen to memory DC
        let _ = BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY);

        // Get bitmap bits
        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = width;
        bmi.bmiHeader.biHeight = -height; // Top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB.0 as u32;

        let mut buffer: Vec<u8> = vec![0; (width * height * 4) as usize];
        
        let _ = GetDIBits(
            hdc_screen,
            hbm,
            0,
            height as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut bmi,
            DIB_RGB_COLORS,
        );

        // Cleanup GDI
        SelectObject(hdc_mem, h_old);
        let _ = DeleteObject(hbm);
        let _ = DeleteDC(hdc_mem);
        let _ = ReleaseDC(hwnd, hdc_screen);

        // Convert BGRA to RGBA for image crate and verify display content
        let mut non_black_count: usize = 0;
        for chunk in buffer.chunks_exact_mut(4) {
            let b = chunk[0];
            let g = chunk[1];
            let r = chunk[2];
            if r > 15 || g > 15 || b > 15 {
                non_black_count += 1;
            }
            chunk[0] = r;
            chunk[2] = b;
            chunk[3] = 255; // Alpha
        }

        if non_black_count >= 100 {
            if let Some(img) = image::ImageBuffer::<image::Rgba<u8>, _>::from_raw(width as u32, height as u32, buffer) {
                let _ = img.save("C:\\Users\\Public\\monitorix_screenshot.png");
            }
        }
    }
}

#[cfg(not(windows))]
fn main() {
    println!("Only supported on Windows.");
}
