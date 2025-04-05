use std::collections::HashMap;
use super::fs;
use super::SahneError;
use core::str::as_bytes;

pub struct MipsAssembler {
    label_addresses: HashMap<String, u32>,
}

impl MipsAssembler {
    pub fn new() -> Self {
        MipsAssembler {
            label_addresses: HashMap::new(),
        }
    }

    pub fn assemble(&mut self, assembly_code: &str) -> Result<Vec<u8>, String> {
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();
        let mut address: u32 = 0; // Program sayacı

        // Birinci geçiş: Etiket adreslerini topla
        for line in lines.clone() { // lines.clone() ile ikinci geçiş için hatları tekrar kullanıyoruz
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue; // Boş satırları ve yorumları atla
            }

            if line.ends_with(':') {
                let label = line.trim_end_matches(':').to_string();
                self.label_addresses.insert(label, address);
            } else {
                address += 4; // Her talimat 4 bayt varsayalım (MIPS için tipik)
            }
        }

        // İkinci geçiş: Makine kodunu oluştur
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.ends_with(':') {
                continue; // Boş satırları, yorumları ve etiket satırlarını atla
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let instruction = parts[0].to_lowercase();
            let arguments = &parts[1..];

            match instruction.as_str() {
                "add" => {
                    // R-tipi talimatı: add rd, rs, rt
                    if arguments.len() != 3 {
                        return Err(format!("Yanlış argüman sayısı {} talimatı için: beklenen 3", instruction));
                    }
                    let rd = self.register_to_binary(arguments[0])?;
                    let rs = self.register_to_binary(arguments[1])?;
                    let rt = self.register_to_binary(arguments[2])?;
                    let opcode = 0b000000; // özel kodu
                    let funct = 0b100000;  // işlev kodu for add
                    let shamt = 0b00000;    // shift miktar, add için 0
                    let instruction_binary: u32 = (opcode << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct;
                    machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                },
                "addi" => {
                    // I-tipi talimatı: addi rt, rs, immediate
                    if arguments.len() != 3 {
                        return Err(format!("Yanlış argüman sayısı {} talimatı için: beklenen 3", instruction));
                    }
                    let rt = self.register_to_binary(arguments[0])?;
                    let rs = self.register_to_binary(arguments[1])?;
                    let immediate = arguments[2].parse::<i16>().map_err(|_| format!("Geçersiz hemen değer: {}", arguments[2]))?;
                    let opcode = 0b001000; // opcode for addi
                    let instruction_binary: u32 = (opcode << 26) | (rs << 21) | (rt << 16) | (immediate as u16 as u32); //işaretsiz 16-bit hemen
                    machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                },
                "lw" => {
                    // I-tipi talimatı: lw rt, offset(rs)
                    if arguments.len() != 2 {
                        return Err(format!("Yanlış argüman sayısı {} talimatı için: beklenen 2", instruction));
                    }
                    let rt = self.register_to_binary(arguments[0])?;
                    let offset_parts: Vec<&str> = arguments[1].split('(').collect();
                    if offset_parts.len() != 2 {
                        return Err(format!("Geçersiz bellek ofseti formatı: {}", arguments[1]));
                    }
                    let offset = offset_parts[0].parse::<i16>().map_err(|_| format!("Geçersiz ofset değeri: {}", offset_parts[0]))?;
                    let rs_arg = offset_parts[1].trim_end_matches(')');
                    let rs = self.register_to_binary(rs_arg)?;
                    let opcode = 0b100011; // opcode for lw
                    let instruction_binary: u32 = (opcode << 26) | (rs << 21) | (rt << 16) | (offset as u16 as u32);
                    machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                },
                "sw" => {
                    // I-tipi talimatı: sw rt, offset(rs)
                    if arguments.len() != 2 {
                        return Err(format!("Yanlış argüman sayısı {} talimatı için: beklenen 2", instruction));
                    }
                    let rt = self.register_to_binary(arguments[0])?;
                    let offset_parts: Vec<&str> = arguments[1].split('(').collect();
                    if offset_parts.len() != 2 {
                        return Err(format!("Geçersiz bellek ofseti formatı: {}", arguments[1]));
                    }
                    let offset = offset_parts[0].parse::<i16>().map_err(|_| format!("Geçersiz ofset değeri: {}", offset_parts[0]))?;
                    let rs_arg = offset_parts[1].trim_end_matches(')');
                    let rs = self.register_to_binary(rs_arg)?;
                    let opcode = 0b101011; // opcode for sw
                    let instruction_binary: u32 = (opcode << 26) | (rs << 21) | (rt << 16) | (offset as u16 as u32);
                    machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                },
                "j" => {
                    // J-tipi talimatı: j target_label
                    if arguments.len() != 1 {
                        return Err(format!("Yanlış argüman sayısı {} talimatı için: beklenen 1", instruction));
                    }
                    let label = arguments[0];
                    let label_address = self.label_addresses.get(label).ok_or_else(|| format!("Tanımsız etiket: {}", label))?;
                    // Hedef adres, kelime adreslemesi olduğu için 4'e bölünür
                    let target_address = label_address / 4;
                    let opcode = 0b000010; // opcode for j
                    // 26-bit hedef adres
                    let instruction_binary: u32 = (opcode << 26) | (target_address & 0x3FFFFFF); // 26-bit maske uygula
                    machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                },
                _ => {
                    return Err(format!("Bilinmeyen talimat: {}", instruction));
                }
            }
        }

        Ok(machine_code)
    }

    fn register_to_binary(&self, register: &str) -> Result<u32, String> {
        match register {
            "$zero" | "$0" => Ok(0),
            "$at" | "$1" => Ok(1),
            "$v0" | "$2" => Ok(2),
            "$v1" | "$3" => Ok(3),
            "$a0" | "$4" => Ok(4),
            "$a1" | "$5" => Ok(5),
            "$a2" | "$6" => Ok(6),
            "$a3" | "$7" => Ok(7),
            "$t0" | "$8" => Ok(8),
            "$t1" | "$9" => Ok(9),
            "$t2" | "$10" => Ok(10),
            "$t3" | "$11" => Ok(11),
            "$t4" | "$12" => Ok(12),
            "$t5" | "$13" => Ok(13),
            "$t6" | "$14" => Ok(14),
            "$t7" | "$15" => Ok(15),
            "$s0" | "$16" | "$fp" => Ok(16),
            "$s1" | "$17" => Ok(17),
            "$s2" | "$18" => Ok(18),
            "$s3" | "$19" => Ok(19),
            "$s4" | "$20" => Ok(20),
            "$s5" | "$21" => Ok(21),
            "$s6" | "$22" => Ok(22),
            "$s7" | "$23" => Ok(23),
            "$t8" | "$24" => Ok(24),
            "$t9" | "$25" => Ok(25),
            "$k0" | "$26" => Ok(26),
            "$k1" | "$27" => Ok(27),
            "$gp" | "$28" => Ok(28),
            "$sp" | "$29" => Ok(29),
            "$s8" | "$30" | "$fp" => Ok(30), // not a typo, $fp can be $s8 or $s30 depending on context
            "$ra" | "$31" => Ok(31),
            _ => Err(format!("Geçersiz register: {}", register)),
        }
    }

    // Assembly kodunu bir dosyadan okuyarak derleme fonksiyonu
    pub fn assemble_from_file(&mut self, file_path: &str) -> Result<Vec<u8>, String> {
        match self.read_file_to_string(file_path) {
            Ok(assembly_code) => self.assemble(&assembly_code),
            Err(e) => Err(format!("Assembly dosyası okuma hatası: {:?}", e)),
        }
    }

    // Üretilen makine kodunu bir dosyaya yazma fonksiyonu
    pub fn write_machine_code_to_file(&self, file_path: &str, machine_code: &[u8]) -> Result<(), SahneError> {
        match fs::open(file_path, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC) {
            Ok(fd) => {
                match fs::write(fd, machine_code) {
                    Ok(_) => {
                        let _ = fs::close(fd);
                        Ok(())
                    }
                    Err(e) => {
                        let _ = fs::close(fd);
                        Err(e)
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    // Dosya içeriğini string olarak okuma (Sahne64 fs kullanarak)
    fn read_file_to_string(&self, file_path: &str) -> Result<String, SahneError> {
        match fs::open(file_path, fs::O_RDONLY) {
            Ok(fd) => {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match fs::read(fd, &mut chunk) {
                        Ok(bytes_read) => {
                            if bytes_read == 0 {
                                break;
                            }
                            buffer.extend_from_slice(&chunk[..bytes_read]);
                        }
                        Err(e) => {
                            let _ = fs::close(fd);
                            return Err(e);
                        }
                    }
                }
                let _ = fs::close(fd);
                match String::from_utf8(buffer) {
                    Ok(s) => Ok(s),
                    Err(_) => Err(SahneError::Other("Dosya UTF-8 formatında değil".to_string())),
                }
            }
            Err(e) => Err(e),
        }
    }
}