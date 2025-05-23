// utils.rs
#![no_std]

use sahne64::utils::{String, Vec, HashMap};
use sahne64::{print, println};

/// Belirli bir hizalamaya göre bir değeri yukarı yuvarlar.
/// Örneğin, 8 bayt hizalama için `align_up(10, 8)` -> 16 döner.
pub fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return value; // Hizalama 0 ise değişiklik yapma
    }
    (value + alignment - 1) & !(alignment - 1)
}

/// İki dilimi (slice) karşılaştırır. Eşitlerse true döner.
/// Bu, `==` operatörü yerine `no_std` ortamında doğrudan karşılaştırma gerektiren durumlar için kullanışlı olabilir.
pub fn slice_equal(s1: &[u8], s2: &[u8]) -> bool {
    if s1.len() != s2.len() {
        return false;
    }
    for i in 0..s1.len() {
        if s1[i] != s2[i] {
            return false;
        }
    }
    true
}

/// `data` içinde `pattern` diliminin ilk geçtiği indeksi bulur.
/// Bulamazsa `None` döner.
pub fn find_pattern_in_slice(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() {
        return Some(0);
    }
    if data.len() < pattern.len() {
        return None;
    }

    for i in 0..=data.len() - pattern.len() {
        if slice_equal(&data[i..i + pattern.len()], pattern) {
            return Some(i);
        }
    }
    None
}

/// Verilen bir 64-bit sayıyı belirtilen offset'ten başlayarak dilime (slice) little-endian olarak yazar.
/// `data`nın boyutu yeterli olmalıdır.
pub fn write_u64_le(data: &mut [u8], offset: usize, value: u64) {
    if offset + 8 > data.len() {
        eprintln!("UYARI: write_u64_le: Offset veya boyut yetersiz. Offset: {}, Value: 0x{:x}", offset, value);
        return; // Hata veya panic yerine uyarı verelim
    }
    let bytes = value.to_le_bytes();
    data[offset..offset + 8].copy_from_slice(&bytes);
}

/// Verilen bir 32-bit sayıyı belirtilen offset'ten başlayarak dilime (slice) little-endian olarak yazar.
/// `data`nın boyutu yeterli olmalıdır.
pub fn write_u32_le(data: &mut [u8], offset: usize, value: u32) {
    if offset + 4 > data.len() {
        eprintln!("UYARI: write_u32_le: Offset veya boyut yetersiz. Offset: {}, Value: 0x{:x}", offset, value);
        return;
    }
    let bytes = value.to_le_bytes();
    data[offset..offset + 4].copy_from_slice(&bytes);
}

/// Verilen bir 16-bit sayıyı belirtilen offset'ten başlayarak dilime (slice) little-endian olarak yazar.
/// `data`nın boyutu yeterli olmalıdır.
pub fn write_u16_le(data: &mut [u8], offset: usize, value: u16) {
    if offset + 2 > data.len() {
        eprintln!("UYARI: write_u16_le: Offset veya boyut yetersiz. Offset: {}, Value: 0x{:x}", offset, value);
        return;
    }
    let bytes = value.to_le_bytes();
    data[offset..offset + 2].copy_from_slice(&bytes);
}

/// Belirtilen offset'ten başlayarak dilimden (slice) bir 64-bit sayıyı little-endian olarak okur.
/// `data`nın boyutu yeterli olmalıdır.
pub fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        eprintln!("UYARI: read_u64_le: Okuma hatası. Offset: {}, Data boyutu: {}", offset, data.len());
        return 0; // Hata yerine 0 döner veya panic atar
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Belirtilen offset'ten başlayarak dilimden (slice) bir 32-bit sayıyı little-endian olarak okur.
/// `data`nın boyutu yeterli olmalıdır.
pub fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        eprintln!("UYARI: read_u32_le: Okuma hatası. Offset: {}, Data boyutu: {}", offset, data.len());
        return 0;
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&data[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

/// Belirtilen offset'ten başlayarak dilimden (slice) bir 16-bit sayıyı little-endian olarak okur.
/// `data`nın boyutu yeterli olmalıdır.
pub fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        eprintln!("UYARI: read_u16_le: Okuma hatası. Offset: {}, Data boyutu: {}", offset, data.len());
        return 0;
    }
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&data[offset..offset + 2]);
    u16::from_le_bytes(bytes)
}

// Byte dizisinden bir dize okur (null-terminated string).
// Maksimum `max_len` kadar karakteri okur veya null terminatöre kadar.
pub fn read_null_terminated_string(data: &[u8], offset: usize, max_len: usize) -> String {
    let mut end = offset;
    while end < data.len() && (end - offset) < max_len && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end])
}
