#![no_std]

extern "C" {
    pub fn scan_pattern_asm(
        buf_ptr: *const u8,
        buf_len: usize,
        pattern_ptr: *const u8,
        pattern_len: usize,
    ) -> i64;
}


pub fn asm_scan(buffer: &[u8], pattern: &[u8]) -> Option<usize> {
    if buffer.is_empty() || pattern.is_empty() || buffer.len() < pattern.len() {
        return None;
    }

    let res = unsafe {
        scan_pattern_asm(
            buffer.as_ptr(),
            buffer.len(),
            pattern.as_ptr(),
            pattern.len(),
        )
    };

    if res < 0 {
        None
    } else {
        Some(res as usize)
    }
}
