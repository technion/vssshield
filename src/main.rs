#![allow(clippy::upper_case_acronyms)]

use std::env;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("Loading vssshield");
    let args: Vec<String> = env::args().collect();

    // When used, "vssadmin delete shadows" becomes "\path\vssshield.exe vssadmin delete shadows"
    if args.len() < 2 {
        print_help();
        return;
    }
    run_if_safe(&args).ok();
}

fn run_if_safe(args: &[String]) -> Result<(), &str> {
    // Caller may or may not have used full pathnames or included extension
    let filename = Path::new(&args[1]);
    match filename.file_name().unwrap().to_str() {
        Some("vssadmin.exe" | "vssadmin") => process_vssadmin(args),
        Some("wmic.exe" | "wmic") => process_wmic(args),
        Some("diskshadow.exe" | "diskshadow") => process_diskshadow(args),
        _ => return Err("Not a supported executable"),
    };

    Ok(())
}

fn purge_with_fire() {
    // if this function has been called - everything is going bad

    // Terminate the parent process.
    use sysinfo::{ProcessExt, System, SystemExt};
    let mut sys = System::new();
    let pid = sysinfo::get_current_pid().unwrap(); // Fails "if platform is unsupported" and this should not fail on Windows
    sys.refresh_process(pid);
    match sys.process(pid) {
        Some(p) => {
            // Obtain a Process struct
            if let Some(parentpid) = p.parent() {
                sys.refresh_process(parentpid);
                eprintln!("Terminating {:?}", parentpid);

                #[cfg(not(test))]
                if let Some(parentprocess) = sys.process(parentpid) {
                    parentprocess.kill();
                }
            }
        }
        None => {
            panic!("Internal error identifying malicious process");
        }
    }
}
fn process_vssadmin(cmd: &[String]) {
    let allowed_commands = ["add", "list"];
    if cmd.len() > 2 && !allowed_commands.contains(&cmd[2].as_str()) {
        purge_with_fire();
        panic!("Failed to terminate");
    }

    launch_debug("c:\\windows\\system32\\vssadmin.exe", &cmd[2..]);
}

fn process_diskshadow(cmd: &[String]) {
    // wmic has far too many legitimate commands to use an allow list
    let deny_commands = ["shadowcopy", "break"];
    if cmd.len() > 2 && deny_commands.contains(&cmd[2].to_lowercase().as_str()) {
        purge_with_fire();
        panic!("Failed to terminate");
    }
    launch_debug("C:\\WINDOWS\\System32\\Wbem\\wmic.exe", &cmd[2..]);
}

fn process_wmic(cmd: &[String]) {
    // wmic has far too many legitimate commands to use an allow list
    let deny_commands = ["delete", "shadowstorage"];
    if cmd.len() > 2 && deny_commands.contains(&cmd[2].to_lowercase().as_str()) {
        purge_with_fire();
        panic!("Failed to terminate");
    }
    launch_debug("C:\\WINDOWS\\System32\\Wbem\\wmic.exe", &cmd[2..]);
}

fn print_help() {
    let display = r##"
    ====================
    Lolware.net
    ====================
    "##;

    println!("{}", display);
}

#[cfg(windows)]
fn launch_debug(cmd: &str, args: &[String]) {
    // https://github.com/rust-lang/rust/blob/756ffb8d0b4f6748c471bbb2075a6ac2bbea29b5/library/std/src/process/tests.rs#L354
    // It appears that sys::c::{BOOL, DWORD, INFINITE}; requires nightly? Implemented manually below.
    type DWORD = u32; // https://stdrs.dev/nightly/x86_64-unknown-linux-gnu/std/sys/c/type.DWORD.html
    type BOOL = i32; // https://stdrs.dev/nightly/x86_64-unknown-linux-gnu/std/sys/c/type.BOOL.html
    const INFINITE: u32 = 4_294_967_295;

    #[repr(C, packed)]
    struct DEBUG_EVENT {
        pub event_code: DWORD,
        pub process_id: DWORD,
        pub thread_id: DWORD,
        // This is a union in the real struct, but we don't
        // need this data for the purposes of this test.
        pub _junk: [u8; 164],
    }

    extern "system" {
        fn WaitForDebugEvent(lpDebugEvent: *mut DEBUG_EVENT, dwMilliseconds: DWORD) -> BOOL;
        fn ContinueDebugEvent(
            dwProcessId: DWORD,
            dwThreadId: DWORD,
            dwContinueStatus: DWORD,
        ) -> BOOL;
    }

    const DEBUG_PROCESS: DWORD = 1;
    const DEBUG_ONLY_THIS_PROCESS: DWORD = 2;
    const EXIT_PROCESS_DEBUG_EVENT: DWORD = 5;
    const DBG_EXCEPTION_NOT_HANDLED: DWORD = 0x8001_0001;

    Command::new(cmd)
        .creation_flags(DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)
        .args(args)
        .spawn()
        .expect("Failed to run process");

    let mut events = 0;
    let mut event = DEBUG_EVENT {
        event_code: 0,
        process_id: 0,
        thread_id: 0,
        _junk: [0; 164],
    };
    loop {
        if unsafe { WaitForDebugEvent(&mut event as *mut DEBUG_EVENT, INFINITE) } == 0 {
            panic!("WaitForDebugEvent failed!");
        }
        events += 1;

        if event.event_code == EXIT_PROCESS_DEBUG_EVENT {
            break;
        }

        if unsafe {
            ContinueDebugEvent(event.process_id, event.thread_id, DBG_EXCEPTION_NOT_HANDLED)
        } == 0
        {
            panic!("ContinueDebugEvent failed!");
        }
    }
    assert!(events > 0);
}

#[cfg(test)]
mod tests {
    use super::run_if_safe;
    #[test]
    fn good_commands_run() {
        let args = vec![
            "vssshield.exe".to_string(),
            "vssadmin.exe".to_string(),
            "list".to_string(),
            "shadows".to_string(),
        ];
        assert!(run_if_safe(&args).is_ok());
        let args2 = vec![
            "vssshield.exe".to_string(),
            "vssadmin.exe".to_string(),
            "list".to_string(),
            "volumes".to_string(),
        ];
        assert!(run_if_safe(&args2).is_ok());
    }

    #[test]
    fn invalid_call() {
        let args = vec!["vssshield.exe".to_string(), "notepad.exe".to_string()];
        assert!(run_if_safe(&args).is_err());
    }

    #[test]
    #[should_panic]
    fn bad_commands_dont() {
        let args = vec![
            "vssshield.exe".to_string(),
            "vssadmin.exe".to_string(),
            "delete".to_string(),
            "shadows".to_string(),
        ];
        run_if_safe(&args).ok();
    }
}
