#![no_std]

use sahne64::utils::String; // no_std uyumlu String

/// Çıktı dosyasının formatını belirtir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    /// Sahne Karnal'a özgü yürütülebilir ikili format.
    /// Genellikle bir tür ELF veya özel bir Karnal formatı olacaktır.
    GaxeExecutable,
    /// ISO 9660 CD/DVD imajı formatı.
    /// Bu, önyüklenebilir bir disk imajı oluşturmak için kullanılır.
    IsoImage,
    // Gelecekte eklenebilecek diğer formatlar:
     RawBinary, // Ham ikili dosya
     Elf,       // Genel ELF formatı (örneğin Linux için)
}

impl core::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OutputFormat::GaxeExecutable => write!(f, "GaxeExecutable"),
            OutputFormat::IsoImage => write!(f, "IsoImage"),
        }
    }
}

/// Linker'ın kullanacağı bağlama tipini belirtir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingType {
    /// Tüm bağımlılıkların doğrudan nihai ikili dosyaya dahil edildiği statik bağlama.
    Static,
    /// Bağımlılıkların çalışma zamanında yüklenen dinamik kütüphanelerden geldiği dinamik bağlama.
    Dynamic,
}

impl core::fmt::Display for BindingType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BindingType::Static => write!(f, "Static"),
            BindingType::Dynamic => write!(f, "Dynamic"),
        }
    }
}

/// Gaxe Linker'ın çalışma zamanı yapılandırmasını tutar.
#[derive(Debug, Clone)]
pub struct LinkerConfig {
    /// Bağlama tipi (statik veya dinamik).
    pub binding_type: BindingType,
    /// Çıktı dosyasının formatı.
    pub output_format: OutputFormat,
    /// Oluşturulacak çıktı dosyasının yolu ve adı.
    pub output_filepath: String,
    /// Programın giriş noktasının sembol adı (örn: `_start`, `main`).
    pub entry_point_symbol: String,
    /// Bellek düzenini ve bölüm yerleşimini tanımlayan bölümlerin listesi.
    /// Bu, .laxe betiğinden ayrıştırılır.
    pub sections: Vec<LinkerSection>,
    /// Ortak kütüphane arama yolları (dinamik bağlama için).
    pub library_paths: Vec<String>,
    /// Bağlanacak özel kütüphanelerin isimleri (örn: "c", "m").
    pub libraries: Vec<String>,
    // Gelecekte eklenebilecek diğer yapılandırma seçenekleri:
     pub debug_output: bool, // Hata ayıklama çıktısı detay seviyesi
     pub strip_symbols: bool, // Sembolleri çıktıdan çıkar
}

impl LinkerConfig {
    /// Yeni bir varsayılan `LinkerConfig` nesnesi oluşturur.
    pub fn new() -> Self {
        LinkerConfig {
            binding_type: BindingType::Static, // Varsayılan statik bağlama
            output_format: OutputFormat::GaxeExecutable, // Varsayılan .gaxe yürütülebilir
            output_filepath: String::from_str("a.out"), // Varsayılan çıktı dosyası
            entry_point_symbol: String::from_str("_start"), // Varsayılan giriş noktası
            sections: Vec::new(),
            library_paths: Vec::new(),
            libraries: Vec::new(),
        }
    }

    /// Bir `LinkerConfig`'in geçerli olup olmadığını kontrol eder.
    /// Basit bir doğrulama örneği.
    pub fn validate(&self) -> bool {
        // En az bir bölüm tanımlanmış mı?
        // Giriş noktası sembolü boş değil mi?
        !self.sections.is_empty() && !self.entry_point_symbol.is_empty() && !self.output_filepath.is_empty()
    }
}

/// Linker betiğinde tanımlanan her bir bölümü temsil eder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkerSection {
    pub name: String,         // Bölüm adı (örn: ".text", ".data")
    pub address: Option<u64>, // Bölümün bellekteki başlangıç adresi (opsiyonel)
    pub align: Option<u64>,   // Bölümün hizalama gereksinimi (opsiyonel)
    // Bu bölümde hangi giriş object dosyalarının yer alacağı gibi bilgiler de eklenebilir.
     pub input_sections: Vec<String>, // Bu bölüme eklenecek giriş bölümleri
}

impl LinkerSection {
    pub fn new(name: String) -> Self {
        LinkerSection {
            name,
            address: None,
            align: None,
        }
    }
}
