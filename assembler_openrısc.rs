use super::fs;
use super::SahneError;
use core::str::as_bytes;

pub struct OpenriscAssembler;

impl OpenriscAssembler {
    pub fn new() -> Self {
        OpenriscAssembler {}
    }

    pub fn assemble_from_file(&self, assembly_file_path: &str) -> Result<Vec<u8>, SahneError> {
        match fs::open(assembly_file_path, fs::O_RDONLY) {
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
                                    return Err(SahneError::InvalidData); // Geçersiz UTF-8
                                }
                            }
                        }
                        Err(e) => {
                            let _ = fs::close(fd);
                            return Err(e);
                        }
                    }
                }
                let _ = fs::close(fd);
                self.assemble_code(&assembly_code)
            }
            Err(e) => Err(e),
        }
    }

    pub fn assemble_code(&self, assembly_code: &str) -> Result<Vec<u8>, String> {
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        for line_num, line in lines.enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(";") {
                continue;
            }

            for byte in line.as_bytes() {
                machine_code.push(*byte);
            }
            machine_code.push(0x0A);

            // **TODO: Gerçek OpenRISC komutlarını ayrıştır ve makine koduna çevir**
        }

        if machine_code.is_empty() && !assembly_code.is_empty() {
            return Err("Assembly kodu işlenemedi veya makine koduna çevrilemedi.".to_string());
        }

        Ok(machine_code)
    }

    pub fn write_machine_code_to_file(&self, machine_code: &[u8], output_file_path: &str) -> Result<(), SahneError> {
        match fs::open(output_file_path, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC) {
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
}