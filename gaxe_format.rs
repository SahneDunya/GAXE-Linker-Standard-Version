#![no_std] // Standart kütüphaneye ihtiyaç duymuyoruz (eğer GAXE no_std ise)

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum Architecture {
    X86 = 0x0001,
    ARM = 0x0002,
    RISCV = 0x0003,
    OpenRISC = 0x0004,
    LoongArch = 0x0005,
    Elbrus = 0x0006,
    MIPS = 0x0007,
    SPARC = 0x0008,
    PowerPC = 0x0009,
}

// Ensure consistent struct layout for binary representation
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GaxeHeader {
    pub magic: u32,         // "GAXE" magic number
    pub version: u32,       // Dosya formatı versiyonu
    pub architecture: Architecture, // Hedef mimari
    pub code_offset: u64,     // Kod bölümünün ofseti
    pub code_size: u64,       // Kod bölümünün boyutu
    pub data_offset: u64,     // Veri bölümünün ofseti
    pub data_size: u64,       // Veri bölümünün boyutu
    // Diğer metaveriler... (Aligned to 64 bytes - padding if needed)
}

#[derive(Debug)]
pub struct GaxeSection {
    pub offset: u64,          // Bölümün ofseti
    pub size: u64,            // Bölümün boyutu
    pub data: Vec<u8>,        // Bölüm verisi
}

#[derive(Debug)]
pub struct GaxeFile {
    pub header: GaxeHeader,
    pub code_section: GaxeSection,
    pub data_section: GaxeSection,
    // Diğer bölümler...
}

// Constants for magic number and version for better readability and maintainability
const GAXE_MAGIC: u32 = 0x47415845; // "GAXE"
const GAXE_VERSION: u32 = 1;
const GAXE_HEADER_SIZE: u64 = core::mem::size_of::<GaxeHeader>() as u64; // Define header size as a constant

impl GaxeFile {
    pub fn new(architecture: Architecture, code: Vec<u8>, data: Vec<u8>) -> Self {
        let code_size = code.len() as u64;
        let data_size = data.len() as u64;

        GaxeFile {
            header: GaxeHeader {
                magic: GAXE_MAGIC, // "GAXE" magic number constant
                version: GAXE_VERSION, // Version constant
                architecture,
                code_offset: GAXE_HEADER_SIZE, // Header size constant
                code_size,
                data_offset: GAXE_HEADER_SIZE + code_size,
                data_size,
            },
            code_section: GaxeSection {
                offset: GAXE_HEADER_SIZE, // Header size constant
                size: code_size,
                data: code,
            },
            data_section: GaxeSection {
                offset: GAXE_HEADER_SIZE + code_size, // Header size + code size
                size: data_size,
                data,
            },
        }
    }

    // .gaxe dosyasını diske yazma fonksiyonu (Sahne64'e özel)
    pub fn write_to_file(&self, filename: &str) -> Result<(), super::SahneError> {
        use super::fs;

        match fs::open(filename, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC) {
            Ok(fd) => {
                // Başlığı yaz
                let header_bytes = unsafe {
                    core::slice::from_raw_parts(
                        &self.header as *const GaxeHeader as *const u8,
                        core::mem::size_of::<GaxeHeader>(),
                    )
                };
                match fs::write(fd, header_bytes) {
                    Ok(bytes_written) if bytes_written as u64 == core::mem::size_of::<GaxeHeader>() as u64 => {
                        // Kod bölümünü yaz
                        match fs::write(fd, &self.code_section.data) {
                            Ok(bytes_written) if bytes_written as u64 == self.code_section.size => {
                                // Veri bölümünü yaz
                                match fs::write(fd, &self.data_section.data) {
                                    Ok(bytes_written) if bytes_written as u64 == self.data_section.size => {
                                        // Dosyayı kapat
                                        let _ = fs::close(fd); // Hata oluşsa bile devam et
                                        Ok(())
                                    }
                                    Ok(_) | Err(_) => {
                                        let _ = fs::close(fd);
                                        Err(super::SahneError::UnknownSystemCall) // Daha spesifik bir hata döndürülebilir
                                    }
                                }
                            }
                            Ok(_) | Err(_) => {
                                let _ = fs::close(fd);
                                Err(super::SahneError::UnknownSystemCall) // Daha spesifik bir hata döndürülebilir
                            }
                        }
                    }
                    Ok(_) | Err(_) => {
                        let _ = fs::close(fd);
                        Err(super::SahneError::UnknownSystemCall) // Daha spesifik bir hata döndürülebilir
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    // .gaxe dosyasını diskten okuma fonksiyonu (Sahne64'e özel)
    pub fn read_from_file(&self, filename: &str) -> Result<Self, super::SahneError> {
        use super::fs;

        match fs::open(filename, fs::O_RDONLY) {
            Ok(fd) => {
                // Başlığı oku
                let mut header_bytes = [0u8; core::mem::size_of::<GaxeHeader>()];
                match fs::read(fd, &mut header_bytes) {
                    Ok(bytes_read) if bytes_read as u64 == core::mem::size_of::<GaxeHeader>() as u64 => {
                        let header = unsafe { *(header_bytes.as_ptr() as *const GaxeHeader) };

                        // ** Magic Number Validation **
                        if header.magic != GAXE_MAGIC {
                            let _ = fs::close(fd);
                            return Err(super::SahneError::InvalidParameter); // Daha uygun bir hata türü seçilebilir
                        }

                        // ** Version Validation **
                        if header.version != GAXE_VERSION {
                            let _ = fs::close(fd);
                            return Err(super::SahneError::InvalidParameter); // Daha uygun bir hata türü seçilebilir
                        }

                        // Kod bölümünü oku
                        let mut code_data = vec![0u8; header.code_size as usize];
                        match fs::read(fd, &mut code_data) {
                            Ok(bytes_read) if bytes_read as u64 == header.code_size => {
                                // Veri bölümünü oku
                                let mut data_data = vec![0u8; header.data_size as usize];
                                match fs::read(fd, &mut data_data) {
                                    Ok(bytes_read) if bytes_read as u64 == header.data_size => {
                                        // Dosyayı kapat
                                        let _ = fs::close(fd);
                                        Ok(GaxeFile {
                                            header,
                                            code_section: GaxeSection {
                                                offset: header.code_offset,
                                                size: header.code_size,
                                                data: code_data,
                                            },
                                            data_section: GaxeSection {
                                                offset: header.data_offset,
                                                size: header.data_size,
                                                data: data_data,
                                            },
                                        })
                                    }
                                    Ok(_) | Err(_) => {
                                        let _ = fs::close(fd);
                                        Err(super::SahneError::UnknownSystemCall) // Daha spesifik bir hata döndürülebilir
                                    }
                                }
                            }
                            Ok(_) | Err(_) => {
                                let _ = fs::close(fd);
                                Err(super::SahneError::UnknownSystemCall) // Daha spesifik bir hata döndürülebilir
                            }
                        }
                    }
                    Ok(_) | Err(_) => {
                        let _ = fs::close(fd);
                        Err(super::SahneError::FileNotFound) // Dosya okuma hatası
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
}