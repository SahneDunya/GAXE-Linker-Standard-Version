use super::fs;
use super::SahneError;

pub struct PowerpcAssembler;

#[derive(Debug, PartialEq, Eq)]
pub enum AssemblerError {
    InvalidInstruction,
    InvalidOperand,
    UnsupportedInstruction,
    SyntaxError(String),
    IOError(SahneError), // SahneError'ı da hata türlerine dahil et
}

// SahneError'ı AssemblerError'a dönüştürmek için
impl From<SahneError> for AssemblerError {
    fn from(err: SahneError) -> Self {
        AssemblerError::IOError(err)
    }
}

impl PowerpcAssembler {
    pub fn new() -> Self {
        PowerpcAssembler {}
    }

    pub fn assemble(&self, assembly_code: &str) -> Result<Vec<u8>, AssemblerError> {
        let mut machine_code = Vec::new();
        for line in assembly_code.lines() {
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
                "addi" => {
                    if parts.len() != 4 {
                        return Err(AssemblerError::SyntaxError(
                            "addi komutu 3 operand gerektirir: addi hedef, kaynak, sabit".to_string()
                        ));
                    }
                    machine_code.extend_from_slice(&[0x38, 0x21, 0x00, 0x0A]);
                }
                "li" => {
                    if parts.len() != 3 {
                        return Err(AssemblerError::SyntaxError(
                            "li komutu 2 operand gerektirir: li hedef, sabit".to_string()
                        ));
                    }
                    machine_code.extend_from_slice(&[0x3c, 0x00, 0x12, 0x34]);
                }
                "b" => {
                    if parts.len() != 2 {
                        return Err(AssemblerError::SyntaxError(
                            "b komutu 1 operand (etiket) gerektirir: b etiket".to_string()
                        ));
                    }
                    machine_code.extend_from_slice(&[0x48, 0x00, 0x00, 0x00]);
                }
                _ => {
                    return Err(AssemblerError::InvalidInstruction);
                }
            }
        }
        Ok(machine_code)
    }

    // Assembly kodunu bir dosyadan okuyup derleme fonksiyonu
    pub fn assemble_from_file(&self, input_filename: &str) -> Result<Vec<u8>, AssemblerError> {
        match fs::open(input_filename, fs::O_RDONLY) {
            Ok(fd) => {
                let mut assembly_code = String::new();
                let mut buffer = [0u8; 1024];
                loop {
                    match fs::read(fd, &mut buffer) {
                        Ok(bytes_read) => {
                            if bytes_read == 0 {
                                break;
                            }
                            match core::str::from_utf8(&buffer[..bytes_read]) {
                                Ok(s) => assembly_code.push_str(s),
                                Err(_) => {
                                    let _ = fs::close(fd);
                                    return Err(AssemblerError::SyntaxError("Geçersiz UTF-8 karakterleri içeriyor".to_string()));
                                }
                            }
                        }
                        Err(e) => {
                            let _ = fs::close(fd);
                            return Err(e.into());
                        }
                    }
                }
                let _ = fs::close(fd);
                self.assemble(&assembly_code)
            }
            Err(e) => Err(e.into()),
        }
    }

    // Üretilen makine kodunu bir dosyaya yazma fonksiyonu
    pub fn write_machine_code_to_file(&self, output_filename: &str, machine_code: &[u8]) -> Result<(), AssemblerError> {
        match fs::open(output_filename, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC) {
            Ok(fd) => {
                match fs::write(fd, machine_code) {
                    Ok(_) => {
                        let _ = fs::close(fd);
                        Ok(())
                    }
                    Err(e) => {
                        let _ = fs::close(fd);
                        Err(e.into())
                    }
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    // Diğer PowerPC assembly işleme fonksiyonları...
}