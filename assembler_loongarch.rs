pub struct LoongarchAssembler;

impl LoongarchAssembler {
    pub fn new() -> Self {
        LoongarchAssembler {}
    }

    /// Verilen dosyadaki LoongArch assembly kodunu okur ve derler.
    pub fn assemble_from_file(&self, input_filename: &str) -> Result<Vec<u8>, super::SahneError> {
        use super::fs;
        use super::SahneError;
        use core::str::from_utf8;

        match fs::open(input_filename, fs::O_RDONLY) {
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
                if let Err(e) = fs::close(fd) {
                    eprintln!("Dosya kapatma hatası: {:?}", e);
                }

                match from_utf8(&buffer) {
                    Ok(assembly_code) => {
                        println!("LoongArch assembly kodu dosyadan okundu: {}", input_filename);
                        Ok(self.assemble_code(assembly_code)) // Asıl derleme işlevini çağır
                    }
                    Err(_) => Err(SahneError::InvalidData), // Geçersiz UTF-8
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Üretilen makine kodunu bir dosyaya yazar.
    pub fn write_machine_code_to_file(&self, output_filename: &str, machine_code: &[u8]) -> Result<(), super::SahneError> {
        use super::fs;
        use super::SahneError;

        match fs::open(output_filename, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC) {
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

    /// Verilen LoongArch assembly kodunu makine koduna çevirir (temel işlev).
    pub fn assemble_code(&self, assembly_code: &str) -> Vec<u8> {
        if assembly_code.is_empty() {
            println!("Uyarı: Assembly kodu boş. Boş bir çıktı üretiliyor.");
            return Vec::new();
        }

        println!("LoongArch assembly kodu derleniyor (basit örnek)...");
        let machine_code = assembly_code.as_bytes().to_vec();
        println!("LoongArch assembly derlemesi tamamlandı (basit örnek). Üretilen makine kodu boyutu: {} bayt.", machine_code.len());
        machine_code
    }

    // Diğer LoongArch assembly işleme fonksiyonları...
}