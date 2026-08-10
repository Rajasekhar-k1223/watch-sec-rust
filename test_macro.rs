macro_rules! hidden_command {
    ($program:expr) => {{
        let mut cmd = std::process::Command::new($program);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        cmd
    }};
}

fn main() {
    let mut cmd = hidden_command!("echo");
    cmd.arg("hello");
    println!("{:?}", cmd);
}
