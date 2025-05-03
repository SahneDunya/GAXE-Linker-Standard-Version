use crate::resource;
use crate::SahneError; // Sahne64 hata türü

use crate::standard_library::StandardLibrary; // StandardLibrary'yi kullanabilmek için

use core::str::as_bytes;
use core::fmt;
use alloc::string::String; // String kullanıldığı için
use alloc::vec::Vec; // Vec kullanıldığı için
use alloc::format; // format! makrosu kullanıldığı için


pub struct ElbrusAssembler {
    // Assembler durumları buraya eklenebilir
    // Örneğin, sembol tablosu, section bilgileri vb.
    // Çıktı almak için StandardLibrary instance'ını tutalım
    standard_library: StandardLibrary,
}

#[derive(Debug)]
pub enum AssemblerError {
    SyntaxError(String),
    UnsupportedInstruction(String),
    UndefinedSymbol(String),
    IOError(SahneError), // SahneError'ı AssemblerError'a dahil et
    // Diğer olası derleyici hataları...
}

// SahneError'dan AssemblerError'a dönüşüm (mevcut ve doğru)
impl From<SahneError> for AssemblerError {
    fn from(err: SahneError) -> Self {
        AssemblerError::IOError(err)
    }
}

// std::error::Error trait implementasyonu std kütüphanesi gerektirir,
// no_std ortamında std::error::Error implementasyonu kullanılamaz
 #[cfg(feature = "std")] // std feature etkinse implemente et
 impl std::error::Error for AssemblerError {}

impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssemblerError::SyntaxError(msg) => write!(f, "Sözdizimi Hatası: {}", msg),
            AssemblerError::UnsupportedInstruction(instruction) => write!(f, "Desteklenmeyen Komut: {}", instruction),
            AssemblerError::UndefinedSymbol(symbol) => write!(f, "Tanımsız Sembol: {}", symbol),
            AssemblerError::IOError(e) => write!(f, "IO Hatası: {:?}", e), // Debug formatı SahneError'ın detayını gösterir
        }
    }
}

impl ElbrusAssembler {
    // StandardLibrary instance'ını constructor'a ekleyelim
    pub fn new(standard_library: StandardLibrary) -> Self {
        ElbrusAssembler {
             standard_library,
            // Diğer durumları başlat...
        }
    }

    pub fn assemble(&self, assembly_code: &str) -> Result<Vec<u8>, AssemblerError> {
        // print_to_stdout yerine self.print_to_stdout'u kullan
        self.print_to_stdout("Elbrus assembly kodu derleniyor...\n")?;

        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') { // Boş satırları ve yorumları atla
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue; // İşlenecek bir şey yoksa devam et
            }

            let instruction = parts[0].to_lowercase(); // Komutu al ve küçük harfe dönüştür
            match instruction.as_str() {
                "nop" => {
                    // NOP komutu için örnek makine kodu (gerçek Elbrus NOP kodunu kullanın)
                    // Elbrus genellikle 64-bit veya 128-bit komutlar kullanır.
                    // Bu sadece bir placeholder.
                    machine_code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Örnek 8-bayt NOP
                }
                "addi" => { // Örnek ADD komutu
                    // ADD komutu için örnek makine kodu (tamamen örnek ve yanlış!)
                    // Gerçek Elbrus komut formatına göre oluşturulmalıdır.
                    if parts.len() != 4 {
                        return Err(AssemblerError::SyntaxError(format!("'addi' komutu 3 argüman gerektirir, {} tane bulundu.", parts.len() - 1)));
                    }
                    // **DİKKAT:** Bu kısım sadece bir örnektir ve GERÇEK ELBRUS MAKİNE KODU DEĞİLDİR!
                    // Gerçek assembler, register ve immediate değerlerini ayrıştırmalı ve
                    // Elbrus mimarisine uygun makine koduna dönüştürmelidir.
                    machine_code.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // Örnek yanlış 8-bayt kod
                    self.print_to_stdout("Uyarı: 'addi' komutu için sadece örnek makine kodu üretildi. Gerçek uygulama gerekli.\n")?;

                }
                // Diğer Elbrus komutları için durumlar buraya eklenecek...
                // Elbrus'un VLIW (Very Long Instruction Word) yapısı assembly parsing'ini karmaşıklaştırır.
                // Genellikle komutlar 'şablonlar' ve 'işlemler' şeklinde ifade edilir.
                // Örneğin: .template, .operation vb.
                _ => {
                    return Err(AssemblerError::UnsupportedInstruction(instruction.to_string()));
                }
            }
        }

        let message = format!("Elbrus assembly derlemesi tamamlandı. {} bayt makine kodu üretildi.\n", machine_code.len());
        self.print_to_stdout(&message)?; // self.print_to_stdout'u kullan
        Ok(machine_code)
    }

    // Çıktı almak için StandardLibrary'yi kullanan helper fonksiyon
    // Artık doğrudan Sahne64 resource::write çağırmıyor, StandardLibrary çağırıyor
    fn print_to_stdout(&self, s: &str) -> Result<(), AssemblerError> {
        // StandardLibrary'nin print_string fonksiyonu Sahne64 resource::write kullanır
        self.standard_library.print_string(s); // StandardLibrary çağrısı

        // StandardLibrary'nin print_string'i Result dönmüyorsa,
        // buradaki hata dönüş tipi sadece AssemblerError::IOError(..)
        // durumlarını ele almalıdır eğer StandardLibrary'de bir hata olursa.
        // Şu anki StandardLibrary taslağı Result dönmüyor gibi görünüyor.
        // Bu durumda buradan her zaman Ok(()) dönmek gerekir,
        // veya StandardLibrary.print_string Result<_, SahneError> dönecek şekilde güncellenmelidir.
        // Varsayım: StandardLibrary içindeki IO hataları orada hallediliyor veya Result dönüyor.
        // Eğer StandardLibrary::print_string() -> Result<(), SahneError> olsaydı:
         match self.standard_library.print_string(s) {
             Ok(_) => Ok(()),
             Err(e) => Err(e.into()), // SahneError'ı AssemblerError'a çevir
         }
        // Mevcut durumda, StandardLibrary hata döndürmediği için IO hatalarını burada yakalayamayız.
        // Basitlik için OK dönüyoruz.
        Ok(())
    }

    // stderr çıktısı için (StandardLibrary'nin stderr desteği varsa kullanılabilir)
     fn print_to_stderr(&self, s: &str) -> Result<(), AssemblerError> {
    //     // StandardLibrary'nin print_error_string gibi bir fonksiyonu olabilir
          self.standard_library.print_error_string(s);
    //     // Eğer yoksa ve her şey stdout'a gidiyorsa bu fonksiyon stdout'u çağırır veya kaldırılır.
         self.print_to_stdout(s) // Şimdilik stdout'a yönlendiriliyor
     }

    // Not: Dosyadan okuma/yazma (assemble_from_file, write_machine_code_to_file)
    // bu modülde eksik, ancak onlar Sahne64 resource modülünü kullanmalıdır,
    // ArmAssembler örneğindeki gibi.


    // Diğer Elbrus assembly işleme fonksiyonları...
}
