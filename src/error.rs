// error.rs
#![no_std]

use sahne64::utils::String;
use sahne64::{print, println};

/// Linker'a özgü tüm hata türlerini kapsayan ana enum.
#[derive(Debug, Clone)]
pub enum LinkerError {
    /// Genel bir I/O hatası (dosya okuma/yazma vb.).
    Io(String),
    /// Geçersiz veya bozuk ELF dosya formatı.
    ElfParsing(String),
    /// Sembol çözümleme sırasında oluşan hatalar.
    SymbolResolution(SymbolResolutionError),
    /// Yeniden konumlandırma (relocation) sırasında oluşan hatalar.
    Relocation(RelocationError),
    /// Çıktı dosyası yazılırken oluşan hatalar.
    OutputWrite(OutputWriteError),
    /// Dinamik bağlama sırasında oluşan hatalar.
    DynamicLinker(DynamicLinkerError),
    /// Linker yapılandırma hatası.
    Config(String),
    /// Desteklenmeyen özellik veya durum.
    Unsupported(String),
    /// Dahili Linker hatası (beklenmeyen bir durum).
    Internal(String),
}

/// Sembol çözümleme sırasında ortaya çıkan belirli hatalar.
#[derive(Debug, Clone)]
pub enum SymbolResolutionError {
    /// Birden fazla sembol tanımı bulundu.
    MultipleDefinitions(String, String, String), // Sembol adı, ilk dosya, ikinci dosya
    /// Tanımlanmamış sembol bulundu.
    UndefinedSymbol(String, String),             // Sembol adı, referans veren dosya
    /// Giriş noktası sembolü bulunamadı.
    EntryPointNotFound(String),                  // Sembol adı
}

/// Yeniden konumlandırma sırasında ortaya çıkan belirli hatalar.
#[derive(Debug, Clone)]
pub enum RelocationError {
    /// Desteklenmeyen bir yeniden konumlandırma tipi.
    UnsupportedRelocationType(String), // Relocation tipi (adı veya ID'si)
    /// Yeniden konumlandırma değeri hedef alana sığmıyor.
    ValueOutOfRange(String),           // Hatanın detayları
    /// Yeniden konumlandırma için hizalama hatası.
    UnalignedRelocation(String),       // Hatanın detayları
    /// Yeniden konumlandırmanın uygulandığı hedef bölüm bulunamadı.
    TargetSectionNotFound(String),     // Hatanın detayları
    /// Desteklenmeyen bir mimari için yeniden konumlandırma denemesi.
    UnsupportedArchitecture(String),   // Mimari adı veya ID'si
}

/// Çıktı dosyası yazılırken ortaya çıkan belirli hatalar.
#[derive(Debug, Clone)]
pub enum OutputWriteError {
    /// Çıktı dosyası oluşturulamıyor veya yazılamıyor.
    FileCreation(String),      // Dosya yolu veya hata detayı
    /// Geçersiz çıktı formatı belirtildi.
    InvalidOutputFormat(String), // Format adı
    /// Gerekli bir bölüm verisi bulunamadı.
    MissingSectionData(String), // Bölüm adı
}

/// Dinamik bağlama sırasında ortaya çıkan belirli hatalar.
#[derive(Debug, Clone)]
pub enum DynamicLinkerError {
    /// Gerekli paylaşılan kütüphane bulunamadı.
    LibraryNotFound(String), // Kütüphane adı
    /// Kütüphanenin yüklenmesi veya ayrıştırılması sırasında hata.
    LibraryLoadError(String), // Kütüphane adı, hata detayı
    /// Dinamik sembol çözümlemesi sırasında hata.
    DynamicSymbolResolution(String), // Sembol adı
    /// Çalışma zamanı dinamik bağlama hatası.
    RuntimeError(String),    // Hata detayı
}


/// Tüm hata enum'ları için ortak Result tipi.
/// Bu, fonksiyonların hata döndürme şeklini basitleştirir.
pub type Result<T> = core::result::Result<T, LinkerError>;

impl From<core::fmt::Error> for LinkerError {
    fn from(err: core::fmt::Error) -> Self {
        LinkerError::Internal(String::from_format_args!("Format hatası: {:?}", err))
    }
}


// --- Hata Mesajlarını Yazdırma Yardımcı Fonksiyonu (Opsiyonel ama kullanışlı) ---
// Bu, hata durumlarında kullanıcıya daha anlamlı mesajlar sağlamak için kullanılabilir.
// Sahne Karnal'ın `print` makrosunu kullanarak çıktı verir.

impl LinkerError {
    pub fn print_error(&self) {
        eprintln!("\nERROR: Linker Hatası!");
        match self {
            LinkerError::Io(msg) => eprintln!("I/O Hatası: {}", msg),
            LinkerError::ElfParsing(msg) => eprintln!("ELF Ayrıştırma Hatası: {}", msg),
            LinkerError::SymbolResolution(e) => {
                eprint!("Sembol Çözümleme Hatası: ");
                match e {
                    SymbolResolutionError::MultipleDefinitions(sym, file1, file2) => {
                        eprintln!("'{}' sembolü birden fazla kez tanımlanmış: {} ve {}", sym, file1, file2);
                    },
                    SymbolResolutionError::UndefinedSymbol(sym, referrer) => {
                        eprintln!("Tanımlanmamış sembol: '{}' (Referans veren: {})", sym, referrer);
                    },
                    SymbolResolutionError::EntryPointNotFound(sym) => {
                        eprintln!("Giriş noktası sembolü bulunamadı: '{}'", sym);
                    },
                }
            },
            LinkerError::Relocation(e) => {
                eprint!("Yeniden Konumlandırma Hatası: ");
                match e {
                    RelocationError::UnsupportedRelocationType(typ) => {
                        eprintln!("Desteklenmeyen yeniden konumlandırma tipi: {}", typ);
                    },
                    RelocationError::ValueOutOfRange(msg) => {
                        eprintln!("Değer aralık dışında: {}", msg);
                    },
                    RelocationError::UnalignedRelocation(msg) => {
                        eprintln!("Hizalama hatası: {}", msg);
                    },
                    RelocationError::TargetSectionNotFound(msg) => {
                        eprintln!("Hedef bölüm bulunamadı: {}", msg);
                    },
                    RelocationError::UnsupportedArchitecture(arch) => {
                        eprintln!("Desteklenmeyen mimari: {}", arch);
                    }
                }
            },
            LinkerError::OutputWrite(e) => {
                eprint!("Çıktı Yazma Hatası: ");
                match e {
                    OutputWriteError::FileCreation(path) => {
                        eprintln!("Dosya oluşturulamıyor/yazılamıyor: {}", path);
                    },
                    OutputWriteError::InvalidOutputFormat(format) => {
                        eprintln!("Geçersiz çıktı formatı: {}", format);
                    },
                    OutputWriteError::MissingSectionData(section) => {
                        eprintln!("Gerekli bölüm verisi bulunamadı: {}", section);
                    },
                }
            },
            LinkerError::DynamicLinker(e) => {
                eprint!("Dinamik Bağlama Hatası: ");
                match e {
                    DynamicLinkerError::LibraryNotFound(lib) => {
                        eprintln!("Gerekli kütüphane bulunamadı: {}", lib);
                    },
                    DynamicLinkerError::LibraryLoadError(lib_err) => {
                        eprintln!("Kütüphane yüklenirken/ayrıştırılırken hata: {}", lib_err);
                    },
                    DynamicLinkerError::DynamicSymbolResolution(sym) => {
                        eprintln!("Dinamik sembol çözümlenemedi: {}", sym);
                    },
                    DynamicLinkerError::RuntimeError(msg) => {
                        eprintln!("Çalışma zamanı hatası: {}", msg);
                    },
                }
            },
            LinkerError::Config(msg) => eprintln!("Yapılandırma Hatası: {}", msg),
            LinkerError::Unsupported(msg) => eprintln!("Desteklenmeyen Özellik: {}", msg),
            LinkerError::Internal(msg) => eprintln!("Dahili Linker Hatası: {}", msg),
        }
    }
}
