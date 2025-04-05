use crate::gaxe_format::{Architecture, GaxeFile, GaxeHeader, GaxeSection};
use object::{File, Object, ObjectSection, SectionKind, SymbolKind};
// use std::fs::File as StdFile; // Artık kullanılmıyor
use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use std::path::Path;

pub struct Linker {
    architecture: Architecture,
    object_files: Vec<String>,
    output_file: String,
}

impl Linker {
    pub fn new(architecture: Architecture, object_files: Vec<String>, output_file: String) -> Self {
        Linker {
            architecture,
            object_files,
            output_file,
        }
    }

    pub fn link(&self) -> IoResult<()> {
        let mut code_data = Vec::new();
        let mut data_data = Vec::new();

        println!("Linking object files for {:?} architecture...", self.architecture);

        for object_file_path in &self.object_files {
            println!("Processing object file: {}", object_file_path);
            let object_file = self.read_object_file(object_file_path)?;
            self.process_object_file(&object_file, &mut code_data, &mut data_data)?;
        }

        println!("Creating GAXE file: {}", self.output_file);
        let gaxe_file = GaxeFile::new(self.architecture, code_data, data_data);
        // GaxeFile'ın write_to_file metodu zaten Sahne64'e göre güncellenmişti.
        if let Err(e) = gaxe_file.write_to_file(&self.output_file) {
            return Err(Error::new(
                ErrorKind::Other,
                format!("GAXE dosyası yazma hatası: {:?}", e),
            ));
        }

        println!("Linking completed successfully. GAXE file created at: {}", self.output_file);
        Ok(())
    }

    fn read_object_file(&self, object_file_path: &str) -> IoResult<File> {
        use super::fs;
        use super::SahneError;

        match fs::open(object_file_path, fs::O_RDONLY) {
            Ok(fd) => {
                let mut buffer = Vec::new();
                let mut read_offset = 0;
                let mut chunk = [0u8; 4096]; // Okuma arabelleği boyutu

                loop {
                    match fs::read(fd, &mut chunk) {
                        Ok(bytes_read) => {
                            if bytes_read == 0 {
                                break; // Dosyanın sonuna ulaşıldı
                            }
                            buffer.extend_from_slice(&chunk[..bytes_read]);
                            read_offset += bytes_read;
                        }
                        Err(e) => {
                            let _ = fs::close(fd);
                            return Err(Error::new(
                                ErrorKind::Other,
                                format!("Nesne dosyası okuma hatası: {}: {:?}", object_file_path, self.map_sahne_error_to_io_error(e)),
                            ));
                        }
                    }
                }

                if let Err(e) = fs::close(fd) {
                    eprintln!("Nesne dosyası kapatma hatası: {:?}", e);
                }

                let object_file = object::File::parse(&*buffer).map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!("Nesne dosyası ayrıştırılamadı: {}: {}", object_file_path, e),
                    )
                })?;

                // Mimari kontrolü (isteğe bağlı, object crate zaten kontrol edebilir)
                if object_file.architecture() != self.map_architecture_to_object_arch(self.architecture) {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "Nesne dosyası mimarisi uyumsuz. Linker mimarisi: {:?}, Nesne dosyası mimarisi: {:?}",
                            self.architecture, object_file.architecture()
                        ),
                    ));
                }

                println!(
                    "Nesne dosyası '{}' başarıyla okundu, mimarisi: {:?}",
                    object_file_path, object_file.architecture()
                );
                Ok(object_file)
            }
            Err(e) => {
                Err(Error::new(
                    ErrorKind::NotFound,
                    format!("Nesne dosyası açılamadı: {}: {:?}", object_file_path, self.map_sahne_error_to_io_error(e)),
                ))
            }
        }
    }

    fn process_object_file(
        &self,
        object_file: &File,
        code_data: &mut Vec<u8>,
        data_data: &mut Vec<u8>,
    ) -> IoResult<()> {
        println!("Processing sections in object file...");

        for section in object_file.sections() {
            println!("Section name: '{}', kind: {:?}", section.name().unwrap_or("<unknown>"), section.kind());
            if section.kind() == SectionKind::Text {
                println!("  - Text section found, appending data.");
                if let Some(data) = section.data() {
                    code_data.extend_from_slice(data);
                    println!("    - Appended {} bytes of code data.", data.len());
                }
            } else if section.kind() == SectionKind::Data || section.kind() == SectionKind::Bss { // Bss de veri bölümüne dahil edilebilir.
                println!("  - Data section found (or BSS), appending data.");
                if let Some(data) = section.data() {
                    data_data.extend_from_slice(data);
                    println!("    - Appended {} bytes of data.", data.len());
                }
            } else {
                println!("  - Skipping section.");
            }
        }

        println!("Section processing completed for this object file.");
        Ok(())
    }

    // object crate'in Architecture enum'u ile bizim Architecture enum'umuzu eşlemek için yardımcı fonksiyon
    fn map_architecture_to_object_arch(&self, arch: Architecture) -> object::Architecture {
        match arch {
            Architecture::X86 => object::Architecture::I386,
            Architecture::ARM => object::Architecture::Arm, // veya Arm64'e bağlı olarak
            Architecture::RISCV => object::Architecture::Riscv64, // veya Riscv64'e bağlı olarak
            Architecture::MIPS => object::Architecture::Mips,
            Architecture::PowerPC => object::Architecture::PowerPc,
            Architecture::LoongArch => object::Architecture::LoongArch64, // Tahmini, object crate'de olmayabilir
            Architecture::Elbrus => object::Architecture::UnknownArchitecture, // Kesin eşleşme olmayabilir
            Architecture::OpenRISC => object::Architecture::UnknownArchitecture, // Kesin eşleşme olmayabilir
            Architecture::SPARC => object::Architecture::SpArc,
        // Diğer mimariler için de eşleşmeler ekleyin veya UnknownArchitecture kullanın gerekirse.
            _ => object::Architecture::UnknownArchitecture, // Varsayılan olarak bilinmeyen mimari
        }
    }

    // SahneError'ı std::io::Error'a dönüştürmek için yardımcı fonksiyon
    fn map_sahne_error_to_io_error(&self, error: super::SahneError) -> Error {
        match error {
            super::SahneError::FileNotFound => Error::new(ErrorKind::NotFound, "Dosya bulunamadı"),
            super::SahneError::PermissionDenied => Error::new(ErrorKind::PermissionDenied, "İzin reddedildi"),
            super::SahneError::InvalidFileDescriptor => Error::new(ErrorKind::InvalidInput, "Geçersiz dosya tanımlayıcısı"),
            // Diğer SahneError türlerini de buraya eşleyebilirsiniz
            _ => Error::new(ErrorKind::Other, format!("Sahne hatası: {:?}", error)),
        }
    }
}