pub struct X86Assembler;

impl X86Assembler {
    pub fn assemble(&self, assembly_code: &str) -> Result<Vec<u8>, String> {
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with(";") {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let instruction = parts[0].to_lowercase();

            match instruction.as_str() {
                "mov" => {
                    if parts.len() != 3 {
                        return Err(format!("Yanlış sayıda operand: {}", line));
                    }
                    let dest = parts[1];
                    let src = parts[2];

                    if dest == "eax" && src == "ebx" {
                        machine_code.push(0x89);
                        machine_code.push(0xD8);
                    } else if dest == "eax" && src.starts_with("$") {
                        machine_code.push(0xB8);
                        if let Ok(imm_val) = src[1..].parse::<u32>() {
                            machine_code.extend_from_slice(&imm_val.to_le_bytes());
                        } else {
                            return Err(format!("Geçersiz immediate değer: {}", src));
                        }
                    } else {
                        return Err(format!("Desteklenmeyen MOV varyasyonu veya operandlar: {}", line));
                    }
                }
                "ret" => {
                    machine_code.push(0xC3);
                }
                _ => {
                    return Err(format!("Bilinmeyen komut: {}", instruction));
                }
            }
        }

        Ok(machine_code)
    }

    // Üretilen makine kodunu Sahne64 dosya sistemine yazmak için yeni bir fonksiyon
    pub fn write_machine_code_to_file(&self, filename: &str, machine_code: &[u8]) -> Result<(), super::SahneError> {
        use super::fs;

        match fs::open(filename, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC) {
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

    // Diğer x86 assembly işleme fonksiyonları...
}