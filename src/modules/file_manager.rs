use std::fs;
use std::io::Write;

pub fn upload_file(path: &str, content_base64: &str) -> Result<String, String> {
    println!("[FileManager] Remote upload to {}", path);
    
    // Try to base64-decode first. If decoding fails, fall back to writing raw text
    // (allows plain-text scripts to be dropped without encoding).
    let bytes: Vec<u8> = match base64_decode(content_base64.trim()) {
        Ok(b) => b,
        Err(_) => content_base64.as_bytes().to_vec(),
    };
    
    match fs::File::create(path).and_then(|mut f| f.write_all(&bytes)) {
        Ok(_) => Ok(format!("Successfully wrote {} bytes to {}", bytes.len(), path)),
        Err(e) => Err(format!("Upload failed: {}", e))
    }
}

/// Minimal base64 decoder (avoids pulling in an extra crate dependency).
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [0xffu8; 256];
    for (i, &c) in CHARS.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let input = input.replace('\n', "").replace('\r', "");
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let c0 = bytes[i]; let c1 = bytes[i+1]; let c2 = bytes[i+2]; let c3 = bytes[i+3];
        let v0 = table[c0 as usize]; let v1 = table[c1 as usize];
        let v2 = if c2 == b'=' { 0 } else { table[c2 as usize] };
        let v3 = if c3 == b'=' { 0 } else { table[c3 as usize] };
        if v0 == 0xff || v1 == 0xff || (c2 != b'=' && v2 == 0xff) || (c3 != b'=' && v3 == 0xff) {
            return Err(());
        }
        out.push((v0 << 2) | (v1 >> 4));
        if c2 != b'=' { out.push((v1 << 4) | (v2 >> 2)); }
        if c3 != b'=' { out.push((v2 << 6) | v3); }
        i += 4;
    }
    Ok(out)
}

pub fn download_file(path: &str) -> Result<String, String> {
    println!("[FileManager] Remote download requested for {}", path);
    
    // Read the file from disk (in a full implementation, this would base64 encode binary files)
    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(e) => Err(format!("Download failed: {}", e))
    }
}
