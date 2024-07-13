#[cfg(test)]
fn crc32c(data: &[u8]) -> u32 {//This is wrong crc32c，just use for my shellcode,resutl same as compute_crc32_simd
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
#[cfg(test)]
fn compute_crc32_simd(data: &[u8]) -> u32 {
    use core::arch::x86_64::*;

    let mut crc: u32 = 0; // CRC 初始值
    for &byte in data {
        crc = unsafe { _mm_crc32_u8(crc, byte) };
    }
    crc // 返回最终的 CRC 值
}
#[cfg(test)]
#[test]
#[allow(non_snake_case)]
fn test_crc(){
    let h = crc32c("GetProcAddress".as_bytes());
    assert_eq!(h,compute_crc32_simd("GetProcAddress".as_bytes()));
    // dbg!(h);
    let GetProcAddress_crc = compute_crc32_simd("GetProcAddress".as_bytes());
    let LoadLibraryA_crc = compute_crc32_simd("LoadLibraryA".as_bytes());
    let ShellExecuteA_crc = compute_crc32_simd("ShellExecuteA".as_bytes());
    let WinExec_crc = compute_crc32_simd("WinExec".as_bytes());
    println!("GetProcAddress crc: 0x{:x}",GetProcAddress_crc);
    println!("LoadLibraryA crc: 0x{:x}",LoadLibraryA_crc);
    println!("ShellExecuteA crc: 0x{:x}",ShellExecuteA_crc);
    println!("WinExec crc: 0x{:x}",WinExec_crc);
    core::hint::black_box(());
}