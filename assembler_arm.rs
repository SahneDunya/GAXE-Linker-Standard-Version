pub mod fs {
    pub use super::super::fs::*; // Sahne64 fs modülünü içeri aktar
}

use super::SahneError;

pub struct ArmAssembler;

#[derive(Debug)]
pub enum AssemblyError {
    SyntaxError(String),
    UnsupportedInstruction(String),
    IOError(SahneError), // SahneError'ı AssemblyError'a dahil et
    // ... diğer hata türleri ...
}

impl From<SahneError> for AssemblyError {
    fn from(err: SahneError) -> Self {
        AssemblyError::IOError(err)
    }
}

impl ArmAssembler {
    pub fn new() -> Self {
        ArmAssembler {}
    }

    pub fn assemble(&self, assembly_code: &str) -> Result<Vec<u8>, AssemblyError> {
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue; // Boş satırları ve yorumları atla
            }

            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.is_empty() {
                continue; // Boş satır (trim sonrası)
            }

            let instruction = parts[0].to_lowercase();

            match instruction.as_str() {
                "mov" => {
                    if parts.len() != 3 {
                        return Err(AssemblyError::SyntaxError(format!("MOV komutu için yanlış argüman sayısı: {}", line)));
                    }
                    println!("MOV komutu bulundu: {}", line);
                    machine_code.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
                },
                "add" => {
                    if parts.len() != 3 {
                        return Err(AssemblyError::SyntaxError(format!("ADD komutu için yanlış argüman sayısı: {}", line)));
                    }
                    println!("ADD komutu bulundu: {}", line);
                    machine_code.extend_from_slice(&[0x10, 0x20, 0x30, 0x40]);
                },
                "sub" => {
                    if parts.len() != 3 {
                        return Err(AssemblyError::SyntaxError(format!("SUB komutu için yanlış argüman sayısı: {}", line)));
                    }
                    println!("SUB komutu bulundu: {}", line);
                    machine_code.extend_from_slice(&[0x50, 0x60, 0x70, 0x80]);
                },
                _ => {
                    return Err(AssemblyError::UnsupportedInstruction(format!("Desteklenmeyen komut: {}", instruction)));
                }
            }
        }

        Ok(machine_code)
    }

    // Assembly kodunu bir dosyadan okuyup derleme fonksiyonu
    pub fn assemble_from_file(&self, file_path: &str) -> Result<Vec<u8>, AssemblyError> {
        match fs::open(file_path, fs::O_RDONLY) {
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
                            return Err(e.into());
                        }
                    }
                }
                if let Err(e) = fs::close(fd) {
                    eprintln!("Dosya kapatma hatası: {:?}", e);
                }
                match String::from_utf8(buffer) {
                    Ok(code) => self.assemble(&code),
                    Err(e) => Err(AssemblyError::SyntaxError(format!("Dosya içeriği UTF-8 değil: {}", e))),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    // Üretilen makine kodunu bir dosyaya yazma fonksiyonu
    pub fn write_machine_code_to_file(&self, file_path: &str, machine_code: &[u8]) -> Result<(), AssemblyError> {
        match fs::open(file_path, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC) {
            Ok(fd) => {
                match fs::write(fd, machine_code) {
                    Ok(_) => {
                        if let Err(e) = fs::close(fd) {
                            eprintln!("Dosya kapatma hatası: {:?}", e);
                        }
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

    // Diğer ARM assembly işleme fonksiyonları...
}