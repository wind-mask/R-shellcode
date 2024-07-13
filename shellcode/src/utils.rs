use core::{ffi::c_void, ptr::null_mut};

use crate::bind::{
    c_char, DWORD, HMODULE, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
    IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64, WORD,
};
pub fn get_fun_from_module_with_crc(ModuleBase: HMODULE,crc:u32) -> *mut c_void {


    let DOS_HEADER: *const IMAGE_DOS_HEADER = ModuleBase as *const _;
    debug_assert!(!DOS_HEADER.is_null());
    debug_assert!(DOS_HEADER.is_aligned());
    let DOS_MAGIC: u16 = unsafe { (*DOS_HEADER).e_magic };
    assert_eq!(DOS_MAGIC, 0x5A4D);
    let NT_HEADER: *const IMAGE_NT_HEADERS64 =
        unsafe { (DOS_HEADER as *const u8).add((*DOS_HEADER).e_lfanew as usize) as *const _ };
    debug_assert!(!NT_HEADER.is_null());
    debug_assert!(NT_HEADER.is_aligned());
    debug_assert_eq!(unsafe { (*NT_HEADER).Signature }, 0x4550);
    let OPTHEADER: *const IMAGE_OPTIONAL_HEADER64 = unsafe { &(*NT_HEADER).OptionalHeader };
    debug_assert!(!OPTHEADER.is_null());
    debug_assert!(OPTHEADER.is_aligned());
    debug_assert_eq!(unsafe { (*OPTHEADER).Magic }, 0x20B);
    let pExport: *const IMAGE_EXPORT_DIRECTORY = unsafe {
        (ModuleBase as *const u8).add(
            (*OPTHEADER).DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress
                as usize,
        ) as *const _
    };

    debug_assert!(!pExport.is_null());
    debug_assert!(pExport.is_aligned());
    let base = unsafe { (*pExport).Base } as usize;
    let pAddOfFun_Raw: *const DWORD = unsafe {
        (ModuleBase as *const u8).add((*pExport).AddressOfFunctions as usize) as *const _
    };
    debug_assert!(!pAddOfFun_Raw.is_null());
    debug_assert!(pAddOfFun_Raw.is_aligned());

    let pAddOfOrd_Raw: *const WORD = unsafe {
        (ModuleBase as *const u8).add((*pExport).AddressOfNameOrdinals as usize) as *const _
    };
    debug_assert!(!pAddOfOrd_Raw.is_null());
    debug_assert!(pAddOfOrd_Raw.is_aligned());
    let pAddOfNames_Raw: *const DWORD =
        unsafe { (ModuleBase as *const u8).add((*pExport).AddressOfNames as usize) as *const _ };

    for i in 0..unsafe { (*pExport).NumberOfFunctions } {
        let name = unsafe {
            (ModuleBase as *const u8).add(pAddOfNames_Raw.add(i as usize).read() as usize)
                as *const c_char
        };
        if compare_raw_cstr_crc(name, crc){
            let ordinal = unsafe { pAddOfOrd_Raw.add(i as usize).read() as usize };
            let rva = unsafe { pAddOfFun_Raw.add(ordinal - base + 1).read() as usize };
            let result = (ModuleBase as usize + rva) as *mut c_void;
            return result;
        } else {
            continue;
        }
    }

    null_mut()
}
fn compare_raw_cstr_crc(p1: *const c_char, crc: u32)-> bool{
    let mut length = 0;
    unsafe {
        // 计算 C 字符串的长度
        let mut temp_ptr = p1;
        while *temp_ptr != 0 {
            temp_ptr = temp_ptr.add(1);
            length += 1;
        }
    }
    
    // 从原始指针创建一个切片
    let slice = unsafe { core::slice::from_raw_parts(p1 as *const u8, length) };
    CRC(slice) == crc
}
#[cfg(not(target_feature="sse4.2"))]
fn CRC(data: &[u8]) -> u32 {
    let mut crc = 0;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
        }
    }
    crc 
}
#[cfg(target_feature="sse4.2")]
fn CRC(data: &[u8]) -> u32 {
    use core::arch::x86_64::*;

    let mut crc: u32 = 0; // CRC 初始值
    for &byte in data {
        crc = unsafe { _mm_crc32_u8(crc, byte) };
    }
    crc // 返回最终的 CRC 值
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_main() {
        let x = crc32fast::hash(b"hello world");
        assert_eq!(x, 0x1ebc6f7f);
    }
}
