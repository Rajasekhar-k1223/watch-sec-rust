fn main() {
    unsafe {
        let mut session_id = 0;
        windows::Win32::System::ProcessStatus::ProcessIdToSessionId(std::process::id(), &mut session_id);
    }
}
