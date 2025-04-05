pub struct RiscvAssembler;

use std::collections::HashMap;
use super::fs;
use super::SahneError;
use core::str::as_bytes;

impl RiscvAssembler {
    pub fn assemble(&self, assembly_code: &str) -> Result<Vec<u8>, String> {
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { // Boş satırları ve yorumları atla
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue; // İşlenecek bir şey yoksa devam et
            }

            let instruction = parts[0].to_lowercase(); // Komutu küçük harfe çevir
            let arguments = &parts[1..];

            match instruction.as_str() {
                "addi" => {
                    // addi rd, rs1, imm
                    if arguments.len() != 3 {
                        return Err(format!("Yanlış sayıda argüman. addi için 3 argüman bekleniyor: {}", line));
                    }
                    let rd = self.parse_register(arguments[0])?;
                    let rs1 = self.parse_register(arguments[1])?;
                    let imm = self.parse_immediate(arguments[2])?;

                    let opcode = 0b0010011; // I-tipi opcode (addi için)
                    let funct3 = 0b000;    // funct3 (addi için)

                    let instruction_bytes = self.encode_i_type(opcode, funct3, funct3, imm, rs1, rd);
                    machine_code.extend_from_slice(&instruction_bytes);
                }
                "li" => {
                    // li rd, imm (pseudo-instruction, basitlik için addi olarak ele alıyoruz)
                    if arguments.len() != 2 {
                        return Err(format!("Yanlış sayıda argüman. li için 2 argüman bekleniyor: {}", line));
                    }
                    let rd = self.parse_register(arguments[0])?;
                    let imm = self.parse_immediate(arguments[1])?;

                    // li rd, imm  ->  addi rd, x0, imm  (x0 sıfır registerı)
                    let opcode = 0b0010011; // I-tipi opcode (addi için)
                    let funct3 = 0b000;    // funct3 (addi için)
                    let rs1 = 0;          // x0 register numarası

                    let instruction_bytes = self.encode_i_type(opcode, funct3, funct3, imm, rs1, rd);
                    machine_code.extend_from_slice(&instruction_bytes);
                }
                "nop" => {
                    // nop (gerçek işlem yok, sadece 4 byte 0 ekliyoruz örnek olarak)
                    let instruction_bytes = [0, 0, 0, 0];
                    machine_code.extend_from_slice(&instruction_bytes);
                }
                _ => {
                    return Err(format!("Bilinmeyen komut: {}", instruction));
                }
            }
        }

        Ok(machine_code)
    }

    // Assembly kodunu bir dosyadan okuyup derleyen yeni bir metot
    pub fn assemble_from_file(&self, filename: &str) -> Result<Vec<u8>, String> {
        match fs::open(filename, fs::O_RDONLY) {
            Ok(fd) => {
                let mut assembly_code = String::new();
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
                            return Err(format!("Dosya okuma hatası: {:?}", e));
                        }
                    }
                }
                if let Err(e) = fs::close(fd) {
                    eprintln!("Dosya kapatma hatası: {:?}", e);
                }
                assembly_code = String::from_utf8(buffer).map_err(|e| format!("UTF-8 dönüşüm hatası: {:?}", e))?;
                self.assemble(&assembly_code)
            }
            Err(e) => Err(format!("Dosya açma hatası: {:?}", e)),
        }
    }

    fn parse_register(&self, reg_str: &str) -> Result<u8, String> {
        if reg_str.starts_with('x') {
            if let Ok(reg_num) = reg_str[1..].parse::<u8>() {
                if reg_num < 32 { // RISC-V'de 32 register var (x0-x31)
                    return Ok(reg_num);
                } else {
                    return Err(format!("Geçersiz register numarası: {}", reg_str));
                }
            } else {
                return Err(format!("Geçersiz register formatı: {}", reg_str));
            }
        } else {
            Err(format!("Geçersiz register formatı: {}", reg_str))
        }
    }

    fn parse_immediate(&self, imm_str: &str) -> Result<i32, String> {
        // Şu anda sadece ondalık sayıları destekliyoruz, gerektiğinde hex vb. destek eklenebilir.
        imm_str.parse::<i32>().map_err(|_| format!("Geçersiz immediate değeri: {}", imm_str))
    }

    // I-tipi komut formatını kodla (opcode, funct3, imm, rs1, rd)
    // Not: Bu çok basit bir örnek, gerçek RISC-V kodlaması daha karmaşık olabilir.
    fn encode_i_type(&self, opcode: u32, funct3: u32, _funct7_shamt: u32, imm: i32, rs1: u8, rd: u8) -> [u8; 4] {
        let mut instruction: u32 = 0;

        instruction |= imm as u32 & 0xFFF; // 12 bit immediate
        instruction |= (rs1 as u32) << 15;   // rs1 (5 bit)
        instruction |= (funct3 as u32) << 12; // funct3 (3 bit)
        instruction |= (rd as u32) << 7;    // rd (5 bit)
        instruction |= opcode << 2;         // opcode (7 bit)

        instruction.to_le_bytes() // Little-endian byte sırası
    }
}