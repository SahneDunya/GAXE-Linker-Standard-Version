// GAXE format yapıları, mimari enum, hata türü
use crate::gaxe_format::{Architecture, GaxeFile, GaxeHeader, GaxeSection, GaxeFileError};

// Nesne dosyası okuma ve ayrıştırma için object crate
use object::{File, Object, ObjectSection, SectionKind, SymbolKind};
// Sahne64 kaynak (dosya) modülü
use crate::resource;
// Sahne64 kaynak tanıtıcısı
use crate::Handle;
// Sahne64 hata türü
use super::SahneError;

// Alloc kütüphanesinden gerekli türler
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

// Core ve Std kütüphanelerinden gerekli türler (genellikle kapsamdadır ama explicit ekleyelim)
use core::fmt;
// Error trait no_std ortamında std feature gerektirebilir
 #[cfg(feature = "std")]
 use std::error::Error;

// Linker'a özgü hata türü
#[derive(Debug)] // Debug çıktısı için
pub enum LinkerError {
    /// Sahne64 kaynaklı IO hataları
    IOError(SahneError),
    /// Nesne dosyasını ayrıştırma hatası
    ParseError(object::Error),
    /// Nesne dosyası mimarisinin linker mimarisiyle uyumsuz olması
    ArchitectureMismatch { linker_arch: Architecture, object_arch: object::Architecture },
    /// Nesne dosyası işlenirken oluşan diğer hatalar (örneğin bölüm verisine erişilememesi)
    ProcessingError(String),
    /// GAXE dosyasına yazma hatası
    GaxeWriteError(GaxeFileError),
     /// Bellek Yetersizliği (object crate'in parse etmesi için veya bölüm birleştirmede)
     AllocationError(String), // Vec::new veya extend_from_slice başarısız olursa
    // Diğer olası linker hataları...
    // Symbol Resolution errors could be added here if symbol linking is implemented.
     UndefinedSymbol(String),
     MultipleDefinition(String),
}

// Trait implementasyonları

impl fmt::Display for LinkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkerError::IOError(e) => write!(f, "IO Hatası: {:?}", e), // SahneError'ın Debug çıktısını kullan
            LinkerError::ParseError(e) => write!(f, "Ayrıştırma Hatası: {}", e), // object::Error'ın Display çıktısını kullan
            LinkerError::ArchitectureMismatch { linker_arch, object_arch } => {
                write!(f, "Mimari Uyumsuzluğu: Linker {:?}, Nesne Dosyası {:?}", linker_arch, object_arch)
            }
            LinkerError::ProcessingError(msg) => write!(f, "İşleme Hatası: {}", msg),
            LinkerError::GaxeWriteError(e) => write!(f, "GAXE Yazma Hatası: {}", e), // GaxeFileError'ın Display çıktısını kullan
            LinkerError::AllocationError(msg) => write!(f, "Tahsis Hatası: {}", msg),
            LinkerError::UndefinedSymbol(s) => write!(f, "Tanımsız Sembol: {}", s),
            LinkerError::MultipleDefinition(s) => write!(f, "Çoklu Tanım: {}", s),
        }
    }
}

// std::error::Error implementasyonu (no_std ortamında std feature gerektirebilir)
 #[cfg(feature = "std")]
 impl std::error::Error for LinkerError {
     fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
         match self {
             LinkerError::IOError(e) => Some(e), // Eğer SahneError Error implement ediyorsa
             LinkerError::ParseError(e) => Some(e),
             LinkerError::GaxeWriteError(e) => Some(e), // Eğer GaxeFileError Error implement ediyorsa
             _ => None,
         }
     }
 }


// Otomatik dönüşümler (From trait)
impl From<SahneError> for LinkerError {
    fn from(err: SahneError) -> Self {
        LinkerError::IOError(err)
    }
}

impl From<object::Error> for LinkerError {
    fn from(err: object::Error) -> Self {
        LinkerError::ParseError(err)
    }
}

impl From<GaxeFileError> for LinkerError {
    fn from(err: GaxeFileError) -> Self {
        LinkerError::GaxeWriteError(err)
    }
}


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

    /// Nesne dosyalarını Sahne64 kaynak sistemi üzerinden okur, bölümlerini birleştirir
    /// ve sonucu Sahne64 kaynak sistemi üzerinden GAXE dosyası olarak yazar.
    pub fn link(&self) -> Result<(), LinkerError> { // Return type changed to custom error
        let mut code_data = Vec::new();
        let mut data_data = Vec::new();

        println!("Linking object files for {:?} architecture...", self.architecture);

        for object_file_path in &self.object_files {
            println!("Processing object file: {}", object_file_path);
             // read_object_file now returns Result<File, LinkerError>
            let object_file = self.read_object_file(object_file_path)?; // Use ? for error propagation
             // process_object_file now returns Result<(), LinkerError>
            self.process_object_file(&object_file, &mut code_data, &mut data_data)?; // Use ?
        }

        println!("Creating GAXE file: {}", self.output_file);
        // GAXE formatının kod offseti 0x1000 gibi bir değer olabilir,
        // Veri offseti kodun bittiği yerden başlar.
        // Sembol çözümleme bu aşamada yapılmalıdır.
        // Bu basit linkerda sembol çözme atlanıyor ve kod/data ardışık yerleştiriliyor.

        let code_offset = 0x1000; // Örnek: Kod bölümü başlangıcı (genellikle programın ilk adresi)
        let data_offset = code_offset + code_data.len() as u64; // Veri bölümü koddan sonra başlar

        // Giriş noktası (entry point) nesne dosyalarından bir sembol olarak çözülmelidir.
        // Basitlik için şimdilik 0x1000 olarak varsayalım (kodun başlangıcı).
        let entry_point = code_offset; // Gerçekte sembol tablosundan çözülmeli

        let gaxe_file = GaxeFile::from_sections( // Use from_sections or similar helper
            self.architecture,
            entry_point,
            code_offset,
            &code_data,
            data_offset,
            &data_data, // Data section bytes
            0, // BSS size would be calculated during symbol resolution
            // Diğer bölümler (relokasyon, sembol tablosu) burada işlenmelidir
        )?; // GaxeFile::from_sections SahneError veya format hatası dönebilir, LinkerError'a çevrilir.

        // GaxeFile'ın write_to_file metodu Sahne64 resource modülünü kullanır.
          write_to_file returns Result<(), GaxeFileError>
        gaxe_file.write_to_file(&self.output_file)?; // Use ? for GaxeFileError propagation

        println!("Linking completed successfully. GAXE file created at: {}", self.output_file);
        Ok(())
    }

    /// Sahne64 kaynak sistemi üzerinden nesne dosyasını okur ve ayrıştırır.
    fn read_object_file(&self, object_file_path: &str) -> Result<File, LinkerError> { // Return type changed
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // fs::O_RDONLY yerine resource::MODE_READ kullan
        match resource::acquire(object_file_path, resource::MODE_READ) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                let mut buffer = Vec::new(); // Dosya içeriğini toplamak için Vec<u8> kullan
                let mut chunk = [0u8; 4096]; // Okuma için ara bellek

                // Sahne64 resource::read kullanarak dosyadan oku
                // fs::read(fd, &mut chunk) yerine resource::read(file_handle, &mut chunk) kullan
                loop {
                    match resource::read(file_handle, &mut chunk) {
                        Ok(bytes_read) => {
                            if bytes_read == 0 { // Dosya sonuna gelindi
                                break;
                            }
                            // Okunan chunk'ı buffer'a ekle
                            // Bellek tahsisi hatası olabilir, LinkerError::AllocationError olarak ele alabiliriz.
                            if let Err(e) = buffer.try_reserve(bytes_read) {
                                 let _ = resource::release(file_handle); // Dosyayı kapatmaya çalış
                                 return Err(LinkerError::AllocationError(format!("Bellek tahsisi hatası: {}", e)));
                            }
                            buffer.extend_from_slice(&chunk[..bytes_read]);
                        }
                        Err(e) => {
                            // Hata oluşursa dosyayı kapat (release) ve hatayı propagate et
                            let _ = resource::release(file_handle); // Dosyayı kapatmaya çalış
                            // SahneError'ı LinkerError::IOError'a çevir
                            return Err(e.into()); // From<SahneError> implementasyonu kullanılır
                        }
                    }
                }

                // Dosya okuma bitti, dosyayı kapat (release)
                // fs::close(fd) yerine resource::release(file_handle) kullan
                if let Err(e) = resource::release(file_handle) {
                    eprintln!("Dosya kapatma hatası (okuma): {:?}", e);
                     // Kapatma hatası önemliyse burada da dönebilirsiniz
                      return Err(e.into()); // SahneError'ı LinkerError::IOError'a çevir
                }

                // Okunan byte'ları object crate ile ayrıştır
                // object::File::parse returns Result<File, object::Error>
                let object_file = object::File::parse(&*buffer)?; // Use ? for object::Error propagation (From<object::Error> implementasyonu kullanılır)

                // Mimari kontrolü
                  object::File::architecture() returns object::Architecture
                 let object_arch = object_file.architecture();
                 let linker_arch = self.map_architecture_to_object_arch(self.architecture);

                if object_arch != linker_arch && linker_arch != object::Architecture::UnknownArchitecture { // Linker unknown değilse karşılaştır
                    return Err(LinkerError::ArchitectureMismatch { // Custom error variant
                        linker_arch: self.architecture, // Store our enum variant
                        object_arch: object_arch, // Store object's enum variant
                    });
                }

                println!(
                    "Nesne dosyası '{}' başarıyla okundu, mimarisi: {:?}",
                    object_file_path, object_arch // Use object_arch directly
                );
                Ok(object_file) // Başarılı sonuç dön
            }
            // Dosya açma hatasını propagate et (SahneError -> LinkerError)
            Err(e) => Err(e.into()), // From<SahneError> implementasyonu kullanılır
        }
    }

    /// Nesne dosyasındaki bölümleri işler ve kod/veri vektörlerine ekler.
    /// Sembol çözme veya yeniden konumlandırma yapmaz (basit linker).
    fn process_object_file(
        &self,
        object_file: &File,
        code_data: &mut Vec<u8>,
        data_data: &mut Vec<u8>,
    ) -> Result<(), LinkerError> { // Return type changed to custom error
        println!("Processing sections in object file...");

        for section in object_file.sections() {
            let section_name = section.name().unwrap_or("<unknown>");
            println!("Section name: '{}', kind: {:?}", section_name, section.kind());

            // object crate'in section.data() metodu Option<&[u8]> döndürür.
            // Hata durumu, data'ya erişilemezse veya beklenmedik bir durum olursa oluşabilir.
            // Bu basit linkerda data'ya erişilememesi ProcessingError olarak ele alınabilir.

             let section_data = section.data().map_err(|e| {
                 // object::Error'dan gelen hata object::Error olarak sarılacak.
                 LinkerError::ParseError(e) // Veya daha spesifik ProcessingError(format!(...))
             })?; // object::Error'ı LinkerError::ParseError'a map et.

             if section.kind() == SectionKind::Text {
                 println!("  - Text section found, appending data ({} bytes).", section_data.len());
                 // Bellek tahsisi hatası olabilir.
                  if let Err(e) = code_data.try_reserve(section_data.len()) {
                      return Err(LinkerError::AllocationError(format!("Kod bölümü birleştirilirken bellek hatası: {}", e)));
                  }
                 code_data.extend_from_slice(section_data);

             } else if section.kind() == SectionKind::Data {
                 println!("  - Data section found, appending data ({} bytes).", section_data.len());
                 // Bellek tahsisi hatası olabilir.
                  if let Err(e) = data_data.try_reserve(section_data.len()) {
                     return Err(LinkerError::AllocationError(format!("Veri bölümü birleştirilirken bellek hatası: {}", e)));
                  }
                 data_data.extend_from_slice(section_data);

             } else if section.kind() == SectionKind::Bss {
                 println!("  - BSS section found. Note: BSS size should be tracked for runtime allocation.");
                 // BSS bölümü bellekte sıfırlarla doldurulur. Linker sadece boyutunu bilmelidir.
                 // Bu basit linkerda BSS boyutu takip edilmiyor ve sıfır data eklenmiyor.
                 // Gerçek bir linker burada BSS boyutunu toplar.
                  let bss_size = section.size();
                  println!("    - BSS size: {} bytes.", bss_size);
                  // Eğer BSS datası varsa (örneğin bazı formatlarda), append edilebilir veya yoksayılabilir.
                  // object crate genellikle BSS için boş slice döndürür.
                   if !section_data.is_empty() {
                        println!("    - Warning: BSS section contains non-zero data. Appending {} bytes.", section_data.len());
                         if let Err(e) = data_data.try_reserve(section_data.len()) {
                             return Err(LinkerError::AllocationError(format!("BSS bölümü birleştirilirken bellek hatası: {}", e)));
                        }
                        data_data.extend_from_slice(section_data);
                   }


             }
             // Symbol sections, relocation sections, etc. would be processed here in a real linker.
             // For this simple linker, we skip them.
             else if section.kind() == SectionKind::Symbol {
                  println!("  - Symbol section found. Skipping (simple linker).");
             } else if section.kind() == SectionKind::Relocation {
                  println!("  - Relocation section found. Skipping (simple linker).");
             }
             else {
                println!("  - Skipping section '{}' with kind {:?}.", section_name, section.kind());
             }
        }

        println!("Section processing completed for this object file.");
        Ok(()) // Başarılı sonuç dön
    }

    // object crate'in Architecture enum'u ile bizim Architecture enum'umuzu eşlemek için yardımcı fonksiyon
    fn map_architecture_to_object_arch(&self, arch: Architecture) -> object::Architecture {
        match arch {
            Architecture::X86 => object::Architecture::I386,
            Architecture::ARM => object::Architecture::Arm, // veya Arm64'e bağlı olarak
            Architecture::RISCV => object::Architecture::Riscv64, // veya Riscv64'e bağlı olarak
            Architecture::MIPS => object::Architecture::Mips,
            Architecture::PowerPC => object::Architecture::PowerPc,
            Architecture::SPARC => object::Architecture::SpArc,
            Architecture::LoongArch => object::Architecture::UnknownArchitecture, // object crate'de direkt eşleşme olmayabilir
            Architecture::Elbrus => object::Architecture::UnknownArchitecture, // object crate'de direkt eşleşme olmayabilir
        }
    }
}
