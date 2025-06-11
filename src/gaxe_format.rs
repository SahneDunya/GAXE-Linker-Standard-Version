#![no_std] // Standart kütüphaneye ihtiyaç duymuyoruz (eğer GAXE no_std ise)

// Alloc kütüphanesinden gerekli türler
extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

// Core kütüphanesinden gerekli türler
use core::{fmt, mem, slice, ptr};

// Sahne64 kaynak (dosya) modülü
use crate::resource;
// Sahne64 kaynak tanıtıcısı
use crate::Handle;
// Sahne64 hata türü
use super::SahneError;

// std::error::Error trait no_std ortamında std feature gerektirebilir
 #[cfg(feature = "std")]
 use std::error::Error;


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
// #[repr(C)] makes layout C-compatible, useful for casting raw bytes.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GaxeHeader {
    pub magic: u32,         // "GAXE" magic number
    pub version: u32,       // Dosya formatı versiyonu
    pub architecture: Architecture, // Hedef mimari
    pub entry_point: u64,   // Programın başlangıç adresi
    pub code_offset: u64,     // Kod bölümünün ofseti
    pub code_size: u64,       // Kod bölümünün boyutu
    pub data_offset: u64,     // Veri bölümünün ofseti
    pub data_size: u64,       // Veri bölümünün boyutu
    // Diğer metaveriler... (Toplam 64 bayt veya daha fazla olabilir, padding gerekirse eklenir)
    // pub padding: [u8; ...], // Align to 64 bytes if needed
}

// Header size constant based on the struct
const GAXE_HEADER_SIZE: u64 = mem::size_of::<GaxeHeader>() as u64;

// Constants for magic number and version for better readability and maintainability
const GAXE_MAGIC: u32 = 0x47415845; // "GAXE"
const GAXE_VERSION: u32 = 1;

#[derive(Debug)]
pub struct GaxeSection {
    pub offset: u64,          // Bölümün ofseti
    pub size: u64,            // Bölümün boyutu
    pub data: Vec<u8>,        // Bölüm verisi (read'de doldurulur)
}

#[derive(Debug)]
pub struct GaxeFile {
    pub header: GaxeHeader,
    pub code_section: GaxeSection,
    pub data_section: GaxeSection,
    // Diğer bölümler (örneğin sembol tablosu, relokasyon) buraya eklenebilir.
}

// GAXE dosyası okuma/yazma sırasında oluşabilecek hatalar
#[derive(Debug)]
pub enum GaxeFileError {
    /// Sahne64 kaynaklı IO hataları
    IOError(SahneError),
    /// Geçersiz "magic number"
    InvalidMagic,
    /// Desteklenmeyen dosya formatı versiyonu
    InvalidVersion,
    /// Beklenmeyen dosya sonu
    UnexpectedEof,
    /// Dosya formatı veya bölüm yerleşiminde hata
    InvalidSectionLayout(String),
    /// Dosyadan okuma sırasında hata
    ReadError(String),
    /// Dosyaya yazma sırasında hata (örneğin kısmi yazma)
    WriteError(String),
     /// Bellek tahsisi hatası
     AllocationError(String),
    // Diğer olası GAXE format hataları
}

// Trait implementasyonları

impl fmt::Display for GaxeFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GaxeFileError::IOError(e) => write!(f, "IO Hatası: {:?}", e), // SahneError'ın Debug çıktısını kullan
            GaxeFileError::InvalidMagic => write!(f, "Geçersiz GAXE magic number."),
            GaxeFileError::InvalidVersion => write!(f, "Desteklenmeyen GAXE versiyonu."),
            GaxeFileError::UnexpectedEof => write!(f, "Beklenmeyen dosya sonu."),
            GaxeFileError::InvalidSectionLayout(msg) => write!(f, "Geçersiz bölüm yerleşimi: {}", msg),
            GaxeFileError::ReadError(msg) => write!(f, "GAXE okuma hatası: {}", msg),
            GaxeFileError::WriteError(msg) => write!(f, "GAXE yazma hatası: {}", msg),
             GaxeFileError::AllocationError(msg) => write!(f, "Bellek tahsisi hatası: {}", msg),
        }
    }
}

// std::error::Error implementasyonu (no_std ortamında std feature gerektirebilir)
 #[cfg(feature = "std")]
 impl std::error::Error for GaxeFileError {
     fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
         match self {
             GaxeFileError::IOError(e) => Some(e), // Eğer SahneError Error implement ediyorsa
             _ => None,
         }
     }
 }


// Otomatik dönüşüm (From trait)
impl From<SahneError> for GaxeFileError {
    fn from(err: SahneError) -> Self {
        GaxeFileError::IOError(err)
    }
}

 // Helper function to read exactly `size` bytes from `handle` into `buffer`
 // Returns the number of bytes read, or error. Ensures exact read or error.
 fn read_exact_into_buffer(handle: Handle, buffer: &mut [u8]) -> Result<(), GaxeFileError> {
     let mut total_read = 0;
     let mut remaining = buffer.len();
     let mut current_buffer = buffer;

     while remaining > 0 {
         match resource::read(handle, current_buffer) {
             Ok(0) => {
                 // Unexpected EOF
                 return Err(GaxeFileError::UnexpectedEof);
             }
             Ok(bytes_read) => {
                 total_read += bytes_read;
                 remaining -= bytes_read as usize;
                 current_buffer = &mut current_buffer[bytes_read as usize..];
             }
             Err(e) => {
                 // IO error during read
                 return Err(e.into()); // From<SahneError> implementasyonu kullanılır
             }
         }
     }
     Ok(()) // Successfully read exactly buffer.len() bytes
 }

 // Helper function to write exactly `data.len()` bytes to `handle`
 // Returns Ok(()) on success, or error. Ensures exact write or error.
  fn write_exact_from_slice(handle: Handle, data: &[u8]) -> Result<(), GaxeFileError> {
      let mut total_written = 0;
      let mut remaining = data.len();
      let mut current_data = data;

      while remaining > 0 {
          match resource::write(handle, current_data) {
               // Although write is not guaranteed to write all bytes,
               // resource::write in Sahne64 might abstract this, or we might need
               // to loop like read_exact_into_buffer. Assuming resource::write
               // returns number of bytes written.
              Ok(0) => {
                  // Should not happen unless handle is closed or invalid
                  return Err(GaxeFileError::WriteError(format!("Zero bytes written unexpectedly")));
              }
              Ok(bytes_written) => {
                  total_written += bytes_written;
                  remaining -= bytes_written as usize;
                  current_data = &current_data[bytes_written as usize..];
              }
              Err(e) => {
                  // IO error during write
                  return Err(e.into()); // From<SahneError> implementasyonu kullanılır
              }
          }
      }
      Ok(()) // Successfully written exactly data.len() bytes
  }


impl GaxeFile {
    /// Yeni bir GaxeFile oluşturur. Kod ve veri bölümleri varsayılan ofsetlerde yerleştirilir.
    /// Entry point kodun başlangıcı olarak varsayılır.
    pub fn new(architecture: Architecture, code: Vec<u8>, data: Vec<u8>) -> Self {
        let code_size = code.len() as u64;
        let data_size = data.len() as u64;

        // Varsayılan ofsetler: Header, sonra kod, sonra data
        let code_offset = GAXE_HEADER_SIZE;
        let data_offset = code_offset + code_size;
        let entry_point = code_offset; // Varsayılan entry point

        GaxeFile {
            header: GaxeHeader {
                magic: GAXE_MAGIC,
                version: GAXE_VERSION,
                architecture,
                entry_point, // Entry point eklendi
                code_offset,
                code_size,
                data_offset,
                data_size,
            },
            code_section: GaxeSection {
                offset: code_offset,
                size: code_size,
                data: code,
            },
            data_section: GaxeSection {
                offset: data_offset,
                size: data_size,
                data,
            },
        }
    }

     /// Bölüm verileri ve ofsetleri verildiğinde bir GaxeFile oluşturur.
     /// Linkerlar için daha uygun olabilir.
     pub fn from_sections(
         architecture: Architecture,
         entry_point: u64,
         code_offset: u64,
         code_data: &[u8], // &[] slice al, Vec<u8> klonlanacak
         data_offset: u64,
         data_data: &[u8], // &[] slice al, Vec<u8> klonlanacak
         bss_size: u64, // BSS boyutu takip edilebilir
     ) -> Result<Self, GaxeFileError> {
         let code_size = code_data.len() as u64;
         let data_size = data_data.len() as u64;

         // Temel Offset/Size validasyonları
         if code_offset < GAXE_HEADER_SIZE || data_offset < GAXE_HEADER_SIZE ||
            data_offset < code_offset + code_size {
             return Err(GaxeFileError::InvalidSectionLayout(format!(
                 "Geçersiz bölüm ofsetleri: code_offset=0x{:X}, data_offset=0x{:X}, code_size=0x{:X}, header_size=0x{:X}",
                 code_offset, data_offset, code_size, GAXE_HEADER_SIZE
             )));
         }
          // Entry point code section içinde mi? Veya geçerli bir adreste mi?
          // Basit kontrol: header/code offset + code size arasında mı? Daha gelişmiş kontroller gerekebilir.
          if entry_point < code_offset || entry_point >= code_offset + code_size {
               // Bu validasyon çok basit, entry point .text section'ın başında olmayabilir.
               // Linker'ın sorumluluğunda olan bir sembol adresidir aslında.
               // Burda sadece temel bir check yapalım veya atlayalım. Şimdilik atlayalım.
          }


         // Veri klonlama (Vec<u8> runtime'da tutulacak)
         let code_vec = Vec::from(code_data); // Veya code_data.to_vec()
         let data_vec = Vec::from(data_data); // Veya data_data.to_vec()

         Ok(GaxeFile {
             header: GaxeHeader {
                 magic: GAXE_MAGIC,
                 version: GAXE_VERSION,
                 architecture,
                 entry_point, // Belirtilen entry point
                 code_offset,
                 code_size,
                 data_offset,
                 data_size,
             },
             code_section: GaxeSection {
                 offset: code_offset,
                 size: code_size,
                 data: code_vec,
             },
             data_section: GaxeSection {
                 offset: data_offset,
                 size: data_size,
                 data: data_vec,
             },
             // BSS boyutu header'a veya ayrı bir bölüme eklenebilir.
         })
     }


    /// .gaxe dosyasını Sahne64 kaynak sistemine yazar.
    pub fn write_to_file(&self, filename: &str) -> Result<(), GaxeFileError> { // Return type changed
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // Bayrakları güncelle: fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC
        // resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE kullan
        match resource::acquire(filename, resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                // Başlığı yaz
                let header_bytes = unsafe {
                     // core::slice::from_raw_parts yerine slice::from_raw_parts
                     slice::from_raw_parts(
                        &self.header as *const GaxeHeader as *const u8,
                        mem::size_of::<GaxeHeader>(),
                    )
                };
                // write_exact_from_slice helper fonksiyonunu kullan
                write_exact_from_slice(file_handle, header_bytes)?; // Propagate GaxeFileError

                // Kod bölümünü yaz
                // write_exact_from_slice helper fonksiyonunu kullan
                write_exact_from_slice(file_handle, &self.code_section.data)?; // Propagate GaxeFileError
                // Yazılan byte sayısı kontrolü artık helper içinde

                // Veri bölümünü yaz
                // write_exact_from_slice helper fonksiyonunu kullan
                write_exact_from_slice(file_handle, &self.data_section.data)?; // Propagate GaxeFileError
                // Yazılan byte sayısı kontrolü artık helper içinde

                // Dosyayı kapat
                // fs::close(fd) yerine resource::release(file_handle) kullan
                 let close_result = resource::release(file_handle); // Hata durumunu kontrol etmek için Result alınır
                 if let Err(e) = close_result {
                    eprintln!("GAXE dosyası kapatma hatası (yazma): {:?}", e);
                     // Kapatma hatasını döndürmek isteyebilirsiniz
                     return Err(e.into()); // SahneError -> GaxeFileError::IOError
                 }

                Ok(()) // Yazma ve kapatma başarılı
            }
            // Dosya açma hatasını propagate et (SahneError -> GaxeFileError)
            Err(e) => Err(e.into()), // From<SahneError> implementasyonu kullanılır
        }
    }

    /// .gaxe dosyasını Sahne64 kaynak sisteminden okur ve ayrıştırır.
    ///
    /// # Arguments
    /// * `filename` - Okunacak GAXE dosyasının yolu.
    ///
    /// # Returns
    /// * `Result<Self, GaxeFileError>` - Başarılı olursa GaxeFile örneği, hata durumunda GaxeFileError.
    pub fn read_from_file(filename: &str) -> Result<Self, GaxeFileError> { // read_from_file should be a static method
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // fs::O_RDONLY yerine resource::MODE_READ kullan
        match resource::acquire(filename, resource::MODE_READ) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                // Başlığı oku
                let mut header_bytes = [0u8; mem::size_of::<GaxeHeader>()];
                // read_exact_into_buffer helper fonksiyonunu kullan
                read_exact_into_buffer(file_handle, &mut header_bytes)?; // Propagate GaxeFileError

                // Güvenli başlık ayrıştırması (unsafe block içinde)
                let header = unsafe { *(header_bytes.as_ptr() as *const GaxeHeader) };

                // ** Validasyonlar **
                if header.magic != GAXE_MAGIC {
                    let _ = resource::release(file_handle);
                    return Err(GaxeFileError::InvalidMagic); // Spesifik hata
                }

                if header.version != GAXE_VERSION {
                    let _ = resource::release(file_handle);
                    return Err(GaxeFileError::InvalidVersion); // Spesifik hata
                }

                 // Bölüm ofset ve boyut validasyonları (Basit kontrol)
                 // Ofsetler header boyutundan büyük veya eşit olmalı
                 // Ofset + Boyut toplam boyuttan büyük olmamalı (Dosya boyutu bilinmiyor burada, stream okuma)
                 // Offsetlerin ardışık ve mantıklı olup olmadığını kontrol et (header -> code -> data)
                if header.code_offset != GAXE_HEADER_SIZE ||
                    header.data_offset != header.code_offset + header.code_size {
                     let _ = resource::release(file_handle);
                     return Err(GaxeFileError::InvalidSectionLayout(format!(
                         "Beklenmeyen bölüm ofsetleri: code_offset=0x{:X} (beklenen 0x{:X}), data_offset=0x{:X} (beklenen 0x{:X})",
                         header.code_offset, GAXE_HEADER_SIZE, header.data_offset, header.code_offset + header.code_size
                     )));
                }

                // Kod bölümünü oku
                // vec![0u8; size] bellek tahsisi hatası verebilir.
                let mut code_data = vec![0u8; header.code_size as usize]; // Potential AllocationError here
                 // read_exact_into_buffer helper fonksiyonunu kullan
                read_exact_into_buffer(file_handle, &mut code_data)?; // Propagate GaxeFileError
                // Okunan byte sayısı kontrolü artık helper içinde

                // Veri bölümünü oku
                // vec![0u8; size] bellek tahsisi hatası verebilir.
                let mut data_data = vec![0u8; header.data_size as usize]; // Potential AllocationError here
                // read_exact_into_buffer helper fonksiyonunu kullan
                read_exact_into_buffer(file_handle, &mut data_data)?; // Propagate GaxeFileError
                // Okunan byte sayısı kontrolü artık helper içinde


                // Dosya okuma bitti, dosyayı kapat (release)
                let close_result = resource::release(file_handle);
                 if let Err(e) = close_result {
                    eprintln!("GAXE dosyası kapatma hatası (okuma): {:?}", e);
                     // Kapatma hatası önemliyse burada da dönebilirsiniz
                      return Err(e.into()); // SahneError -> GaxeFileError::IOError
                 }


                Ok(GaxeFile { // Başarılı sonuç olarak GaxeFile struct'ını dön
                    header, // Okunan header
                    code_section: GaxeSection {
                        offset: header.code_offset, // Header'dan gelen ofset
                        size: header.code_size,   // Header'dan gelen boyut
                        data: code_data,          // Okunan data
                    },
                    data_section: GaxeSection {
                        offset: header.data_offset, // Header'dan gelen ofset
                        size: header.data_size,   // Header'dan gelen boyut
                        data: data_data,          // Okunan data
                    },
                     // Diğer bölümler de okunup struct'a eklenmelidir
                })
            }
            // Dosya açma hatasını propagate et (SahneError -> GaxeFileError)
            Err(e) => Err(e.into()), // From<SahneError> implementasyonu kullanılır
        }
    }
     // read_from_file artık statik bir metot olduğu için self parametresi yok
      pub fn read_from_file(&self, filename: &str) -> Result<Self, super::SahneError> { ... } // İmzası değişti
}
