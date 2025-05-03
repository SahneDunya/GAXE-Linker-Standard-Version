use crate::resource;
use super::SahneError; // Sahne64 hata türü (varsa crate::SahneError olarak değiştirin)
use crate::Handle; // Sahne64 kaynak tanıtıcısı

use alloc::string::{String, ToString}; // String ve ToString trait'i için
use alloc::vec::Vec; // Vec için
use alloc::format; // format! makrosu kullanıldığı için
use core::fmt; // Error Display için
use core::str::from_utf8; // from_utf8 kullanıldığı için (assemble_from_file için)

pub struct X86Assembler;

// x86 Assembler özel hata türleri
#[derive(Debug, PartialEq, Eq)] // fmt::Display de burada derive edilebilir
pub enum AssemblerError {
    SyntaxError(String), // Genel sözdizimi veya diğer ayrıştırma/anlamsal hatalar için detaylı mesaj
    InvalidOperand(String), // İşlenen formatı veya değeri yanlış
    UnsupportedInstruction(String), // Bilinmeyen veya desteklenmeyen komut varyasyonu
    EncodingError(String), // Dosya içeriğinin geçerli UTF-8 olmaması gibi hatalar
    IOError(SahneError), // Sahne64 kaynaklı IO hataları
    // Eğer etiket/sembol desteği eklenirse:
    // UndefinedSymbol(String),
    // MultipleDefinition(String),
    // Diğer olası derleyici hataları...
}

// SahneError'dan AssemblerError::IOError'a dönüşüm
impl From<SahneError> for AssemblerError {
    fn from(err: SahneError) -> Self {
        AssemblerError::IOError(err)
    }
}

 // Hata türünü yazdırılabilir yapmak için Display implementasyonu
impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
             AssemblerError::SyntaxError(msg) => write!(f, "Sözdizimi Hatası: {}", msg),
             AssemblerError::InvalidOperand(msg) => write!(f, "Geçersiz İşlenen: {}", msg),
             AssemblerError::UnsupportedInstruction(instr) => write!(f, "Desteklenmeyen Komut: {}", instr),
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


impl X86Assembler {
     pub fn new() -> Self {
         X86Assembler {
              // Sembol tablosu gibi durumlar buraya eklenebilir:
               label_addresses: alloc::collections::HashMap::new(),
         }
     }

    /// Verilen x86 assembly kodunu derler.
    /// Gerçek derleyici mantığı buraya yazılmalıdır.
    /// Sözdizimi, işlenen hataları vb. için Result<Vec<u8>, AssemblerError> döndürür.
    pub fn assemble(&self, assembly_code: &str) -> Result<Vec<u8>, AssemblerError> { // Return type changed
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        // Etiketler ve ileri referanslar için iki geçişli bir yaklaşım gerekebilir.
        // Bu örnek tek geçişlidir ve etiketleri desteklemez.

        for line_num, line in lines.enumerate() {
             let line = line.trim(); // Satır başı ve sonundaki boşlukları temizle
             if line.is_empty() || line.starts_with(";") || line.starts_with("#") { // x86 yorumları genellikle ; veya # ile başlar
                 continue;
             }

             // Gerçek x86 komutlarını ayrıştır ve makine koduna çevir.
             // Bu kısım çok basitleştirilmiştir ve gerçek assembler mantığını içermez.
             // Örnek olarak MOV ve RET komutlarını ele alalım.

             let parts: Vec<&str> = line.split_whitespace().collect();

             if parts.is_empty() {
                 continue; // Boş satır (boşluklardan sonra)
             }

             let instruction = parts[0].to_lowercase(); // Komutu küçük harfe çevir
             let arguments: Vec<&str> = parts[1..].iter().map(|arg| arg.trim_end_matches(',').trim()).collect(); // Argümanları al ve virgülü/boşlukları temizle

             match instruction.as_str() {
                 "mov" => {
                     // x86 MOV komutunun çok sayıda varyasyonu var.
                     // Bu örnek sadece 'mov eax, ebx' ve 'mov eax, $imm32'yi destekler.
                     if arguments.len() != 2 {
                         return Err(AssemblerError::SyntaxError(format!("Satır {}: 'mov' için yanlış sayıda argüman: beklenen 2, {} bulundu.", line_num + 1, arguments.len())));
                     }
                     let dest = arguments[0];
                     let src = arguments[1];

                     if dest == "eax" && src == "ebx" {
                          // MOV EAX, EBX (Opcode 89 /r, ModR/M: 11 000 011 -> D8)
                          machine_code.extend_from_slice(&[0x89, 0xD8]);
                          println!("  Satır {}: '{}' -> MOV EAX, EBX (0x89D8)", line_num + 1, line);
                     } else if dest == "eax" && src.starts_with("$") {
                          // MOV EAX, imm32 (Opcode B8+rd, rd=0 for EAX)
                          let imm_str = &src[1..]; // '$' işaretini kaldır
                          let imm_val = self.parse_immediate(&imm_str)?; // parse_immediate artık AssemblerError döner

                          // Immediate değeri 32 bit olmalı
                          // x86'da MOV reg, imm komutları immediate'yi 32-bit olarak alır.
                          // Parse_immediate i32 döndürüyor, bunu u32 olarak kullanabiliriz.
                          let imm_u32 = imm_val as u32;

                          machine_code.push(0xB8); // MOV EAX opcode
                          machine_code.extend_from_slice(&imm_u32.to_le_bytes()); // x86 little-endian
                          println!("  Satır {}: '{}' -> MOV EAX, 0x{:x} (0xB8{:08x})", line_num + 1, line, imm_u32, imm_u32);

                     } else {
                         // Desteklenmeyen MOV varyasyonu
                         return Err(AssemblerError::UnsupportedInstruction(format!("Satır {}: Desteklenmeyen 'mov' varyasyonu veya operandlar: {}", line_num + 1, line)));
                     }
                 }
                 "ret" => {
                     // RET (Near return) - Opcode C3
                     machine_code.push(0xC3);
                     println!("  Satır {}: '{}' -> RET (0xC3)", line_num + 1, line);
                 }
                  // x86'da syscall genellikle INT 0x80 veya SYSCALL/SYSENTER ile yapılır.
                  // Assembly düzeyinde bu komutlar direkt olarak kodlanır.
                 "int" => {
                      // INT imm8
                      if arguments.len() != 1 {
                          return Err(AssemblerError::SyntaxError(format!("Satır {}: 'int' için yanlış sayıda argüman: beklenen 1, {} bulundu.", line_num + 1, arguments.len())));
                      }
                      let interrupt_str = arguments[0];
                      let interrupt_num = self.parse_immediate(&interrupt_str)?; // parse_immediate artık AssemblerError döner

                       // Interrupt numarası 8 bit olmalı
                       if interrupt_num < 0 || interrupt_num > 255 {
                            return Err(AssemblerError::InvalidOperand(format!("Satır {}: int immediate değeri 8 bit aralığının dışında ({})", line_num + 1, interrupt_num)));
                       }

                      machine_code.push(0xCD); // INT opcode
                      machine_code.push(interrupt_num as u8); // 8-bit interrupt vector
                       println!("  Satır {}: '{}' -> INT 0x{:x} (0xCD{:02x})", line_num + 1, line, interrupt_num, interrupt_num as u8);
                 }
                  "syscall" => {
                       // SYSCALL (Modern x86_64 Linux Syscall) - Opcode 0F 05
                       // Sadece 64-bit modda kullanılabilir. Varsayımımız 32-bit x86 olduğundan bu komut 32-bit assembly'de genellikle yoktur.
                       // Ancak örneklik için ekleyelim, 32-bit context'te UnsupportedInstruction olarak kabul edilebilir.
                        if !arguments.is_empty() {
                            return Err(AssemblerError::SyntaxError(format!("Satır {}: 'syscall' argüman almaz.", line_num + 1)));
                        }
                        // Assuming 32-bit context, this is Unsupported
                         return Err(AssemblerError::UnsupportedInstruction(format!("Satır {}: 'syscall' komutu 32-bit x86 modunda desteklenmez. 'int 0x80' kullanın.", line_num + 1)));

                        // // If targeting 64-bit:
                         machine_code.extend_from_slice(&[0x0F, 0x05]); // SYSCALL opcode
                         println!("  Satır {}: '{}' -> SYSCALL (0x0F05)", line_num + 1, line);
                  }
                 // ... diğer x86 komutları buraya eklenecek ...
                 _ => {
                     // Bilinmeyen komut mnemoniki
                     return Err(AssemblerError::UnsupportedInstruction(format!("Satır {}: '{}'", line_num + 1, instruction)));
                 }
             }
        }

        // Gerçek bir derleyici burada etiket çözümleme, .data segment işleme vb. yapardı.

         // Eğer hiçbir komut işlenmezse ama assembly kodu boş değilse (yorumlar hariç), bu bir hata olabilir.
         // Bu kontrol assemble_code içinde kalabilir veya çağrılan yerde yapılabilir.
         // Basitlik için burada tutalım.
         if machine_code.is_empty() && !assembly_code.trim().is_empty() {
             // Boş olmayan kodu işlemediysek bu genellikle syntax hatasıdır.
             return Err(AssemblerError::SyntaxError("Assembly kodu işlenemedi veya makine koduna çevrilemedi. Sözdizimini kontrol edin.".to_string()));
         }


        Ok(machine_code) // Başarılı sonuç dön
    }

    /// Assembly kodunu bir dosyadan okuyup derleyen metot.
    /// Sahne64 resource modülünü dosya okuma için kullanır.
    pub fn assemble_from_file(&self, filename: &str) -> Result<Vec<u8>, AssemblerError> { // Return type changed
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // fs::O_RDONLY yerine resource::MODE_READ kullan
        match resource::acquire(filename, resource::MODE_READ) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                let mut buffer = Vec::new(); // Dosya içeriğini toplamak için Vec<u8> kullan
                let mut chunk = [0u8; 1024]; // Okuma için ara bellek

                // Sahne64 resource::read kullanarak dosyadan oku
                // fs::read(fd, &mut chunk) yerine resource::read(file_handle, &mut chunk) kullan
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
                         // self.assemble artık AssemblerError döndürüyor
                         self.assemble(&assembly_code) // Asıl derleme işlevini çağır ve hatayı ? ile ilet
                    }
                     // UTF-8 hatasını AssemblerError::EncodingError'a çevir
                    Err(e) => Err(AssemblerError::EncodingError(format!("Dosya içeriği geçerli UTF-8 değil: {}", e))),
                }
            }
            // Dosya açma hatasını propagate et (SahneError -> AssemblerError)
            Err(e) => Err(e.into()),
        }
    }

     // Üretilen makine kodunu bir dosyaya yazma fonksiyonu
     // Sahne64 resource modülünü dosya yazma için kullanır.
     pub fn write_machine_code_to_file(&self, filename: &str, machine_code: &[u8]) -> Result<(), AssemblerError> { // Return type changed
         // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
         // fs::open yerine resource::acquire kullan
         // Bayrakları güncelle: fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC
         // resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE kullan
         match resource::acquire(filename, resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE) {
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

     // Helper fonksiyonlar (örnek olarak eklendi)
     // x86'da register parsing daha karmaşık olabilir (eax, ax, al vs.)
     // Şu anki kod sadece "eax", "ebx" gibi 32-bit registerları dize olarak kontrol ediyor.
     // Bu fonksiyon daha detaylı parsing yapabilir.
      fn parse_register(&self, reg_str: &str) -> Result<u8, AssemblerError> { /* eax -> 0, ebx -> 3, etc. */ } // Register numarası veya encoding detayı dönebilir


     fn parse_immediate(&self, imm_str: &str) -> Result<i32, AssemblerError> { // Return type changed
          let imm_str = imm_str.trim(); // Trim whitespace
         // Sayı formatlarını destekle (ondalık, onaltılık, ikili)
         if imm_str.starts_with("0x") || imm_str.starts_with("0X") {
              i32::from_str_radix(&imm_str[2..], 16)
                  .map_err(|e| AssemblerError::InvalidOperand(format!("Geçersiz onaltılık immediate değeri '{}': {}", imm_str, e)))
         } else if imm_str.starts_with("0b") || imm_str.starts_with("0B") {
              i32::from_str_radix(&imm_str[2..], 2)
                   .map_err(|e| AssemblerError::InvalidOperand(format!("Geçersiz ikili immediate değeri '{}': {}", imm_str, e)))
         } else {
             // Ondalık sayı
              imm_str.parse::<i32>()
                  .map_err(|e| AssemblerError::InvalidOperand(format!("Geçersiz ondalık immediate değeri '{}': {}", imm_str, e)))
         }
          // Sembol çözme (etiketler) ikinci geçişte veya ayrı bir aşamada yapılır.
          // Şu anda sadece sayısal immediate'leri destekliyoruz.
     }

     // Diğer x86 assembly işleme fonksiyonları...
     // Örneğin: sembol tablosu, ikinci geçiş (adres çözümleme), data section işleme, segment override prefixler, operand size override prefixler, ModR/M byte encoding, SIB byte encoding vb.
}
