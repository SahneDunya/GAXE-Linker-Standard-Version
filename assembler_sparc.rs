use crate::gaxe_format::Architecture;
use crate::standard_library::StandardLibrary; // StandardLibrary'yi içeri aktar

pub struct SparcAssembler {
    standard_library: StandardLibrary, // StandardLibrary örneğini tut
}

impl SparcAssembler {
    pub fn new(architecture: Architecture) -> Self { // Mimariyi alacak şekilde güncellendi
        SparcAssembler {
            standard_library: StandardLibrary::new(architecture), // StandardLibrary'yi başlat
        }
    }

    pub fn assemble(&self, assembly_code: &str) -> Result<Vec<u8>, String> {
        self.standard_library.print_string("SPARC assembly kodu derleniyor...");
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        for line in lines {
            let line = line.trim(); // Satır başı ve sonundaki boşlukları temizle
            if line.is_empty() || line.starts_with("!") || line.starts_with(";") || line.starts_with("#") {
                // Boş satırları ve yorumları atla (!, ;, # ile başlayan satırlar yorum olarak kabul edilir)
                continue;
            }

            // Basitçe satırı kelimelere ayır (gerçek ayrıştırma daha karmaşık olmalı)
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.is_empty() {
                continue; // Boş satır (boşluklardan sonra)
            }

            let instruction = parts[0].to_lowercase(); // Komutu küçük harfe çevir (büyük/küçük harf duyarsızlığı için)

            match instruction.as_str() {
                "nop" => { // "nop" komutu örneği
                    machine_code.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Örnek nop opcode (gerçek opcode farklı olabilir)
                    self.standard_library.print_string("NOP komutu derlendi.");
                }
                "sethi" => { // "sethi" komutu örneği (daha karmaşık)
                    if parts.len() != 3 {
                        return Err(format!("'sethi' komutu için yanlış argüman sayısı: {}", line));
                    }
                    let immediate_str = parts[1];
                    let register = parts[2];

                    let immediate = immediate_str.parse::<u32>().map_err(|e| format!("Geçersiz immediate değeri '{}': {}", immediate_str, e))?;
                    let register_number = self.parse_register(register)?; // Register numarasını ayrıştır

                    // **Örnek sethi opcode oluşturma (basitleştirilmiş ve muhtemelen yanlış)**
                    // Gerçek sethi opcode formatı ve encoding'i SPARC mimari referansından kontrol edilmeli
                    let opcode_base: u32 = 0x04000000; // Örnek base opcode - SETHI için farklı olabilir
                    let opcode = opcode_base | (immediate & 0x3FFFFFFF) | ((register_number as u32) << 25); // Immediate ve register'ı birleştir
                    machine_code.extend_from_slice(&opcode.to_be_bytes()); // Big-endian olarak byte'lara çevir
                    self.standard_library.print_string(&format!("SETHI komutu derlendi: immediate={}, register={}", immediate, register));
                }
                // ... diğer SPARC komutları için case'ler buraya eklenecek ...
                _ => {
                    return Err(format!("Bilinmeyen komut: {}", instruction));
                }
            }
        }

        self.standard_library.print_string(&format!("SPARC assembly derleme işlemi başarıyla tamamlandı. Toplam {} bayt makine kodu üretildi.", machine_code.len()));
        Ok(machine_code)
    }

    fn parse_register(&self, register_str: &str) -> Result<u8, String> {
        // Basit register ayrıştırma fonksiyonu (örneğin %r0, %r1, ..., %r31)
        if !register_str.starts_with("%r") {
            return Err(format!("Geçersiz register formatı: {}", register_str));
        }
        let reg_num_str = &register_str[2..]; // "%r" ön ekini kaldır
        let reg_num = reg_num_str.parse::<u8>().map_err(|e| format!("Geçersiz register numarası '{}': {}", reg_num_str, e))?;
        if reg_num > 31 {
            return Err(format!("Register numarası 0-31 arasında olmalıdır: {}", register_str));
        }
        Ok(reg_num)
    }

    // Diğer SPARC assembly işleme fonksiyonları... (örneğin sembol tablosu yönetimi, yeniden konumlandırma vb.)
}