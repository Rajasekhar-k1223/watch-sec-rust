#[cfg(target_os = "windows")]
pub mod outlook_com {
    use serde_json::{json, Value};
    use std::ptr::null_mut;
    use windows::core::{BSTR, GUID, HRESULT, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED,
        IDispatch, DISPPARAMS, CLSIDFromProgID, EXCEPINFO,
    };
    use windows::Win32::System::Variant::{
        VARIANT, VariantClear, VariantInit, VARIANT_0_0_0,
    };
    use windows::Win32::System::Com::{
        DISPATCH_PROPERTYGET, DISPATCH_METHOD,
    };

    const DISPID_UNKNOWN: i32 = -1;

    unsafe fn get_dispid(dispatch: &IDispatch, name: &str) -> Option<i32> {
        let name_u16: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let name_pwstr = PCWSTR(name_u16.as_ptr());
        let mut dispid = DISPID_UNKNOWN;
        
        let result = dispatch.GetIDsOfNames(
            &GUID::zeroed(),
            &name_pwstr as *const _,
            1,
            2048,
            &mut dispid,
        );
        
        if result.is_ok() {
            Some(dispid)
        } else {
            None
        }
    }

    unsafe fn invoke_method_with_string_arg(dispatch: &IDispatch, name: &str, arg: &str) -> Option<IDispatch> {
        let dispid = get_dispid(dispatch, name)?;
        let mut result = VariantInit();

        let arg_bstr = BSTR::from(arg);
        let mut var_arg = windows::Win32::System::Variant::VARIANT {
            Anonymous: windows::Win32::System::Variant::VARIANT_0 {
                Anonymous: std::mem::ManuallyDrop::new(windows::Win32::System::Variant::VARIANT_0_0 {
                    vt: windows::Win32::System::Variant::VT_BSTR,
                    wReserved1: 0,
                    wReserved2: 0,
                    wReserved3: 0,
                    Anonymous: windows::Win32::System::Variant::VARIANT_0_0_0 {
                        bstrVal: std::mem::ManuallyDrop::new(arg_bstr),
                    },
                }),
            },
        };

        let mut dispparams = DISPPARAMS {
            rgvarg: &mut var_arg as *mut VARIANT,
            rgdispidNamedArgs: null_mut(),
            cArgs: 1,
            cNamedArgs: 0,
        };
        
        let mut excepinfo = EXCEPINFO::default();
        let mut arg_err = 0;
        
        let hr = dispatch.Invoke(
            dispid,
            &GUID::zeroed(),
            2048,
            DISPATCH_METHOD,
            &mut dispparams,
            Some(&mut result),
            Some(&mut excepinfo),
            Some(&mut arg_err),
        );
        
        VariantClear(&mut var_arg);

        if hr.is_ok() {
            if result.Anonymous.Anonymous.vt == windows::Win32::System::Variant::VT_DISPATCH {
                let disp = result.Anonymous.Anonymous.Anonymous.pdispVal.as_ref().cloned();
                VariantClear(&mut result);
                return disp;
            }
            VariantClear(&mut result);
        }
        None
    }

    unsafe fn invoke_method_with_int_arg(dispatch: &IDispatch, name: &str, arg: i32) -> Option<IDispatch> {
        let dispid = get_dispid(dispatch, name)?;
        let mut result = VariantInit();

        let mut var_arg = windows::Win32::System::Variant::VARIANT {
            Anonymous: windows::Win32::System::Variant::VARIANT_0 {
                Anonymous: std::mem::ManuallyDrop::new(windows::Win32::System::Variant::VARIANT_0_0 {
                    vt: windows::Win32::System::Variant::VT_I4,
                    wReserved1: 0,
                    wReserved2: 0,
                    wReserved3: 0,
                    Anonymous: windows::Win32::System::Variant::VARIANT_0_0_0 {
                        lVal: arg,
                    },
                }),
            },
        };

        let mut dispparams = DISPPARAMS {
            rgvarg: &mut var_arg as *mut VARIANT,
            rgdispidNamedArgs: null_mut(),
            cArgs: 1,
            cNamedArgs: 0,
        };
        
        let mut excepinfo = EXCEPINFO::default();
        let mut arg_err = 0;
        
        let hr = dispatch.Invoke(
            dispid,
            &GUID::zeroed(),
            2048,
            DISPATCH_METHOD,
            &mut dispparams,
            Some(&mut result),
            Some(&mut excepinfo),
            Some(&mut arg_err),
        );
        
        if hr.is_ok() {
            if result.Anonymous.Anonymous.vt == windows::Win32::System::Variant::VT_DISPATCH {
                let disp = result.Anonymous.Anonymous.Anonymous.pdispVal.as_ref().cloned();
                VariantClear(&mut result);
                return disp;
            }
            VariantClear(&mut result);
        }
        None
    }

    unsafe fn get_property_dispatch(dispatch: &IDispatch, name: &str) -> Option<IDispatch> {
        let dispid = get_dispid(dispatch, name)?;
        let mut result = VariantInit();
        
        let mut dispparams = DISPPARAMS::default();
        let mut excepinfo = EXCEPINFO::default();
        let mut arg_err = 0;
        
        let hr = dispatch.Invoke(
            dispid,
            &GUID::zeroed(),
            2048,
            DISPATCH_PROPERTYGET,
            &mut dispparams,
            Some(&mut result),
            Some(&mut excepinfo),
            Some(&mut arg_err),
        );
        
        if hr.is_ok() {
            if result.Anonymous.Anonymous.vt == windows::Win32::System::Variant::VT_DISPATCH {
                let disp = result.Anonymous.Anonymous.Anonymous.pdispVal.as_ref().cloned();
                VariantClear(&mut result);
                return disp;
            }
            VariantClear(&mut result);
        }
        None
    }

    unsafe fn get_property_string(dispatch: &IDispatch, name: &str) -> Option<String> {
        let dispid = get_dispid(dispatch, name)?;
        let mut result = VariantInit();
        
        let mut dispparams = DISPPARAMS::default();
        let mut excepinfo = EXCEPINFO::default();
        let mut arg_err = 0;
        
        let hr = dispatch.Invoke(
            dispid,
            &GUID::zeroed(),
            2048,
            DISPATCH_PROPERTYGET,
            &mut dispparams,
            Some(&mut result),
            Some(&mut excepinfo),
            Some(&mut arg_err),
        );
        
        if hr.is_ok() {
            if result.Anonymous.Anonymous.vt == windows::Win32::System::Variant::VT_BSTR {
                let bstr = &result.Anonymous.Anonymous.Anonymous.bstrVal;
                let s = bstr.to_string();
                VariantClear(&mut result);
                return Some(s);
            }
            VariantClear(&mut result);
        }
        None
    }

    unsafe fn get_property_int(dispatch: &IDispatch, name: &str) -> Option<i32> {
        let dispid = get_dispid(dispatch, name)?;
        let mut result = VariantInit();
        
        let mut dispparams = DISPPARAMS::default();
        let mut excepinfo = EXCEPINFO::default();
        let mut arg_err = 0;
        
        let hr = dispatch.Invoke(
            dispid,
            &GUID::zeroed(),
            2048,
            DISPATCH_PROPERTYGET,
            &mut dispparams,
            Some(&mut result),
            Some(&mut excepinfo),
            Some(&mut arg_err),
        );
        
        if hr.is_ok() {
            if result.Anonymous.Anonymous.vt == windows::Win32::System::Variant::VT_I4 {
                let val = result.Anonymous.Anonymous.Anonymous.lVal;
                VariantClear(&mut result);
                return Some(val);
            }
            VariantClear(&mut result);
        }
        None
    }

    pub fn extract_emails() -> Vec<Value> {
        let mut events = Vec::new();
        
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

            let prog_id: Vec<u16> = "Outlook.Application\0".encode_utf16().collect();
            let Ok(clsid) = CLSIDFromProgID(PCWSTR(prog_id.as_ptr())) else {
                crate::log_msg("[MailMonitor] Failed to resolve Outlook.Application CLSID.");
                return events;
            };

            let Ok(dispatch) = CoCreateInstance::<_, IDispatch>(&clsid, None, CLSCTX_LOCAL_SERVER) else {
                crate::log_msg("[MailMonitor] Failed to CoCreateInstance for Outlook.");
                return events;
            };

            let outlook = dispatch;

            let mapi = match invoke_method_with_string_arg(&outlook, "GetNamespace", "MAPI") {
                Some(m) => m,
                None => {
                    crate::log_msg("[MailMonitor] Failed to get MAPI namespace.");
                    return events;
                }
            };

            let sent_folder = match invoke_method_with_int_arg(&mapi, "GetDefaultFolder", 5) {
                Some(f) => f,
                None => {
                    crate::log_msg("[MailMonitor] Failed to get Sent folder.");
                    return events;
                }
            };

            let items = match get_property_dispatch(&sent_folder, "Items") {
                Some(i) => i,
                None => {
                    crate::log_msg("[MailMonitor] Failed to get Items from folder.");
                    return events;
                }
            };

            let count = match get_property_int(&items, "Count") {
                Some(c) => c,
                None => {
                    crate::log_msg("[MailMonitor] Failed to get Items Count.");
                    return events;
                }
            };

            crate::log_msg(&format!("[MailMonitor] Total sent items: {}", count));

            let start = if count > 10 { count - 9 } else { 1 };
            
            for i in start..=count {
                if let Some(mail_item) = invoke_method_with_int_arg(&items, "Item", i) {
                    let subject = get_property_string(&mail_item, "Subject").unwrap_or_default();
                    let sender = get_property_string(&mail_item, "SenderName").unwrap_or_default();
                    let to = get_property_string(&mail_item, "To").unwrap_or_default();
                    let body = get_property_string(&mail_item, "Body").unwrap_or_default();
                    
                    let body_preview: String = body.chars().take(500).collect();

                    events.push(json!({
                        "Sender": sender,
                        "Recipient": to,
                        "Subject": subject,
                        "BodyPreview": body_preview,
                        "HasAttachments": false,
                        "AttachmentNames": "",
                        "Attachments": [],
                    }));
                }
            }
            
            crate::log_msg(&format!("[MailMonitor] Successfully extracted {} emails using native COM VARIANTs.", events.len()));
        }

        events
    }
}
