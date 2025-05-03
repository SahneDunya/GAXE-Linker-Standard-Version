use crate::resource;
use super::SahneError; // Sahne64 hata türü (varsa crate::SahneError olarak değiştirin)
use crate::Handle; // Sahne64 kaynak tanıtıcısı

use alloc::string::String; // String kullanıldığı için
use alloc::vec::Vec; // Vec kullanıldığı için
use alloc::format; // format! makrosu kullanıldığı için
use core::fmt; // Error Display için
use core::str::from_utf8; // from_utf8 kullanıldığı için


pub struct OpenriscAssembler;

// OpenRISC Assembler özel hata türleri
#[derive(Debug, PartialEq, Eq)] // fmt::Display de burada derive edilebilir
pub enum AssemblerError {
    InvalidInstruction, // Bu spesifik hata türlerini koruyalım
    InvalidOperand,
    UnsupportedInstruction,
    SyntaxError(String), // Genel sözdizimi veya diğer ayrıştırma/anlamsal hatalar için detaylı mesaj
    EncodingError(String), // Dosya içeriğinin geçerli UTF-8 olmaması gibi hatalar
    IOError(SahneError), // Sahne64 kaynaklı IO hataları
    // Eğer etiket/sembol desteği eklenirse:
    // UndefinedSymbol(String),
    // MultipleDefinition(String),
    // Diğer olası derleyici hataları...
}

// SahneError'dan AssemblerError::IOError'a dönüşüm (mevcut ve doğru)
impl From<SahneError> for AssemblerError {
    fn from(err: SahneError) -> Self {
        AssemblerError::IOError(err)
    }
}

 // Hata türünü yazdırılabilir yapmak için Display implementasyonu
impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
             AssemblerError::InvalidInstruction => write!(f, "Geçersiz Komut"),
             AssemblerError::InvalidOperand => write!(f, "Geçersiz İşlenen"),
             AssemblerError::UnsupportedInstruction => write!(f, "Desteklenmeyen Komut"),
             AssemblerError::SyntaxError(msg) => write!(f, "Sözdizimi Hatası: {}", msg),
             AssemblerError::EncodingError(msg) => write!(f, "Kodlama Hatası: {}", msg),
             AssemblerError::IOError(e) => write!(f, "IO Hatası: {:?}", e), // SahneError'ın Debug çıktısını kullan
             AssemblerError::UndefinedSymbol(symbol) => write!(f, "Tanımsız Sembol: {}", symbol),
             AssemblerError::MultipleDefinition(symbol) => write!(f, "Sembol Çoklu Tanımlandı: {}", symbol),
        }
    }
}


// std::error::Error trait implementasyonu no_std ortamında std feature gerektirir.
// Eğer std feature yoksa bu kısım koşullu derlenmelidir.
 #[cfg(feature = "std")]
 impl std::error::Error for AssemblerError {}


impl OpenriscAssembler {
    pub fn new() -> Self {
        OpenriscAssembler {
            // Sembol tablosu gibi durumlar buraya eklenebilir:
             label_addresses: alloc::collections::HashMap::new(),
        }
    }

    /// Verilen dosyadaki OpenRISC assembly kodunu okur ve derler.
    /// Sahne64 resource modülünü dosya okuma için kullanır.
    pub fn assemble_from_file(&self, assembly_file_path: &str) -> Result<Vec<u8>, AssemblerError> { // Return type changed
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // fs::O_RDONLY yerine resource::MODE_READ kullan
        match resource::acquire(assembly_file_path, resource::MODE_READ) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                let mut buffer = Vec::new(); // Dosya içeriğini toplamak için Vec<u8> kullan
                let mut chunk = [0u8; 1024]; // Okuma için ara bellek

                // Sahne64 resource::read kullanarak dosyadan oku
                // fs::read(fd, &mut buffer) yerine resource::read(file_handle, &mut chunk) kullan
                loop {
                    match resource::read(file_handle, &mut chunk) {
                        Ok(bytes_read) => {
                            if bytes_read == 0 { // Dosya sonuna gelindi
                                break;
                            }
                            // Okunan chunk'ı buffer'a ekle
                            buffer.extend_from_slice(&chunk[..bytes_read]);
                        }
                        Err(e) => {
                            // Hata oluşursa dosyayı kapat (release) ve hatayı propagate et
                            let _ = resource::release(file_handle); // Dosyayı kapatmaya çalış
                            // SahneError'ı AssemblerError::IOError'a çevir
                            return Err(e.into());
                        }
                    }
                }

                // Dosya okuma bitti, dosyayı kapat (release)
                // fs::close(fd) yerine resource::release(file_handle) kullan
                if let Err(e) = resource::release(file_handle) {
                    eprintln!("Dosya kapatma hatası (okuma): {:?}", e);
                     // Kapatma hatası da döndürülebilir, şu an sadece loglaniyor
                      return Err(e.into());
                }

                // Okunan byte'ları UTF-8 string'e çevir
                match String::from_utf8(buffer) {
                    Ok(assembly_code) => {
                         // self.assemble_code AssemblerError döndürecek şekilde güncellendi
                         self.assemble_code(&assembly_code) // Asıl derleme işlevini çağır
                    }
                     // UTF-8 hatasını AssemblerError::EncodingError'a çevir
                    Err(e) => Err(AssemblerError::EncodingError(format!("Dosya içeriği geçerli UTF-8 değil: {}", e))),
                }
            }
            // Dosya açma hatasını propagate et (SahneError -> AssemblerError)
            Err(e) => Err(e.into()),
        }
    }

    /// Verilen OpenRISC assembly kodunu makine koduna çevirir (temel işlev).
    /// Gerçek derleyici mantığı buraya yazılmalıdır.
    /// Sözdizimi hataları vb. için Result<Vec<u8>, AssemblerError> döndürür.
    pub fn assemble_code(&self, assembly_code: &str) -> Result<Vec<u8>, AssemblerError> { // Return type changed
        if assembly_code.is_empty() {
            println!("Uyarı: Assembly kodu boş. Boş bir çıktı üretiliyor.");
            return Ok(Vec::new()); // Başarılı boş sonuç dön
        }

        println!("OpenRISC assembly kodu derleniyor (basit örnek)...");
        // **DİKKAT:** Bu kısım GERÇEK OpenRISC assembly'e çeviri yapmaz.
        // Gerçek derleyici mantığı (parsing, semantik analiz, kod üretimi) buraya yazılmalıdır.
        // OpenRISC komutları genellikle 32-bit (4 byte) sabittir.
        // Bu süreçte sözdizimi, bilinmeyen komut, yanlış argüman vb. hatalar
        // AssemblerError'ın diğer varyantları olarak döndürülmelidir.

        // Örnek olarak sadece girilen stringi byte dizisine çeviriyor ve newline ekliyor (YANLIŞ MAKİNE KODU ÜRETİR!)
        // Gerçek bir derleyici, her satırdaki komutu ayrıştırır ve uygun 4-bayt makine kodunu üretir.
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        for line_num, line in lines.enumerate() {
             let line = line.trim();
             if line.is_empty() || line.starts_with(";") {
                 continue;
             }
             // ÖRNEK: Gerçek parsing ve kod üretimi burada olurdu.
             // Örnek olarak NOP komutunu tanıyalım:
             let parts: Vec<&str> = line.split_whitespace().collect();
             if parts.is_empty() { continue; }

             let opcode_str = parts[0].to_lowercase();
             match opcode_str.as_str() {
                 "l.nop" => {
                     // l.nop makine kodu (OR R0, R0, 0) - 32-bit (4 byte)
                     machine_code.extend_from_slice(&[0x15, 0x00, 0x00, 0x00]);
                     println!("  Satır {}: '{}' -> l.nop (0x15000000)", line_num + 1, line);
                 },
                 // ... diğer OpenRISC komutları buraya eklenecek ...
                 // Örneğin: l.addi rD, rA, IMM16 -> 0x14 | rA | rD | IMM16 (Big-endian)
                  "l.addi" => {
                       if parts.len() != 4 { return Err(AssemblerError::SyntaxError(format!("Satır {}: addi komutu yanlış argüman sayısı", line_num + 1))); }
                       let rd = self.parse_register(parts[1])?; // rN -> 0..31
                       let ra = self.parse_register(parts[2])?;
                       let imm = self.parse_immediate(parts[3])?; // parse sayı, label vs.
                       if imm < -32768 || imm > 32767 { return Err(AssemblerError::InvalidOperand); } // Check 16-bit range
                       let instruction: u32 = (0x14 << 26) | ((ra & 0x1F) << 21) | ((rd & 0x1F) << 16) | (imm as u16 as u32);
                       machine_code.extend_from_slice(&instruction.to_be_bytes()); // Big-endian
                  },
                  _ => {
                      // Bilinmeyen komut
                      return Err(AssemblerError::UnsupportedInstruction(format!("Satır {}: {}", line_num + 1, line)));
                  }
             }


        }

        println!("OpenRISC assembly derlemesi tamamlandı. Üretilen makine kodu boyutu: {} bayt.", machine_code.len());

        // Gerçek bir derleyici burada oluşabilecek hataları kontrol ederdi.
        // Etiket çözümleme, data section işleme vb.
        // Eğer hiçbir komut işlenmezse ama assembly kodu boş değilse, bu bir hata olabilir.
         if machine_code.is_empty() && !assembly_code.trim().is_empty() {
             return Err(AssemblerError::SyntaxError("Assembly kodu işlenemedi veya makine koduna çevrilemedi.".to_string()));
         }


        Ok(machine_code) // Başarılı sonuç dön
    }

     // Helper fonksiyonlar (örnek olarak eklendi)
      fn parse_register(&self, reg_str: &str) -> Result<u32, AssemblerError> { /* rN -> 0..31 */ }
      fn parse_immediate(&self, imm_str: &str) -> Result<i32, AssemblerError> { /* sayı, etiket vs. */ }


    /// Üretilen makine kodunu bir dosyaya yazar.
    /// Sahne64 resource modülünü dosya yazma için kullanır.
    pub fn write_machine_code_to_file(&self, machine_code: &[u8], output_file_path: &str) -> Result<(), AssemblerError> { // Return type changed
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // Bayrakları güncelle: fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC
        // resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE kullan
        match resource::acquire(output_file_path, resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                // Sahne64 resource::write kullanarak dosyaya yaz
                // fs::write(fd, machine_code) yerine resource::write(file_handle, machine_code) kullan
                match resource::write(file_handle, machine_code) {
                    Ok(bytes_written) => {
                         let close_result = resource::release(file_handle); // Dosyayı kapat

                         if bytes_written as usize != machine_code.len() {
                             // Yazılan byte sayısı beklenenle uyuşmuyorsa hata
                              eprintln!("Uyarı: Tüm makine kodu dosyaya yazılamadı. Yazılan: {}, Beklenen: {}", bytes_written, machine_code.len());
                              // Kapatma hatası olsa bile yazma hatasını döndür
                               if let Err(e) = close_result {
                                   eprintln!("Dosya kapatma hatası (yazma sonrası uyarıda): {:?}", e);
                                   // Kapatma hatası önemliyse burada da dönebilirsiniz
                              }
                               return Err(AssemblerError::IOError(SahneError::CommunicationError)); // Veya daha iyi bir hata
                         }

                         // Yazma başarılı, kapatma hatasını kontrol et
                         if let Err(e) = close_result {
                            eprintln!("Dosya kapatma hatası (yazma): {:?}", e);
                             // Kapatma hatasını döndürmek isteyebilirsiniz
                             return Err(e.into()); // SahneError'ı AssemblerError'a çevir
                         }

                        Ok(()) // Yazma ve kapatma başarılı
                    }
                    Err(e) => {
                        // Yazma hatası oluşursa dosyayı kapat (release) ve hatayı propagate et
                        let _ = resource::release(file_handle); // Dosyayı kapatmaya çalış
                        Err(e.into()) // SahneError'ı AssemblerError'a çevir
                    }
                }
            }
            // Dosya açma hatasını propagate et (SahneError -> AssemblerError)
            Err(e) => Err(e.into()),
        }
    }

    // Diğer OpenRISC assembly işleme fonksiyonları...
    // Örneğin: sembol tablosu, ikinci geçiş (adres çözümleme), data section işleme vb.
}
