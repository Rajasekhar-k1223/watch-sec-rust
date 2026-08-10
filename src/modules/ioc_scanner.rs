use ring::digest::{Context, SHA256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn scan_directory(dir: &str, hashes: Vec<String>) -> Result<Vec<String>, String> {
    let target = Path::new(dir);
    if !target.exists() || !target.is_dir() {
        return Err(format!("Target directory '{}' does not exist or is not a directory", dir));
    }

    // Convert requested hashes to lowercase for case-insensitive matching
    let target_hashes: Vec<String> = hashes.into_iter().map(|h| h.to_lowercase()).collect();
    let mut matches = Vec::new();
    let mut to_visit = vec![target.to_path_buf()];

    while let Some(current_dir) = to_visit.pop() {
        if let Ok(entries) = std::fs::read_dir(&current_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                
                // Do not traverse symlinks to avoid infinite loops or scanning unintended areas
                if path.is_symlink() {
                    continue;
                }

                if path.is_dir() {
                    to_visit.push(path);
                } else if path.is_file() {
                    if let Ok(hash) = hash_file(&path) {
                        if target_hashes.contains(&hash) {
                            matches.push(path.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
    }

    Ok(matches)
}

fn hash_file(path: &PathBuf) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 16384]; // 16KB buffer for faster I/O

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    let digest = context.finish();
    Ok(hex::encode(digest.as_ref()))
}
