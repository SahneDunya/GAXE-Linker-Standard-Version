use crate::resource;
use super::SahneError; // Sahne64 hata türü (varsa crate::SahneError olarak değiştirin)
use crate::Handle; // Sahne64 kaynak tanıtıcısı

// StandardLibrary'yi içeri aktar (çıktı için)
use crate::standard_library::StandardLibrary;

use alloc::string::{String, ToString}; // String ve ToString trait'i için
use alloc::vec::Vec; // Vec için
use alloc::format; // format! makrosu için
use core::fmt; // Error Display için
use core::str::from_utf8; // from_utf8 kullanıldığı için

// SPARC Assembler özel hata türleri
#[derive(Debug)] // PartialEq, Eq, Display de derive edilebilir
pub enum AssemblerError {
    SyntaxError(String), // Genel sözdizimi veya diğer ayrıştırma/anlamsal hatalar için detaylı mesaj
    InvalidOperand(String), // İşlenen formatı veya değeri yanlış
    UnsupportedInstruction(String), // Bilinmeyen veya desteklenmeyen komut mnemonik
    UndefinedSymbol(String), // Eğer etiket/sembol desteği eklenirse
    EncodingError(String), // Dosya içeriğinin geçerli UTF-8 olmaması gibi hatalar
    IOError(SahneError), // Sahne64 kaynaklı IO hataları
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
             AssemblerError::UndefinedSymbol(symbol) => write!(f, "Tanımsız Sembol: {}", symbol),
             AssemblerError::EncodingError(msg) => write!(f, "Kodlama Hatası: {}", msg),
             AssemblerError::IOError(e) => write!(f, "IO Hatası: {:?}", e), // SahneError'ın Debug çıktısını kullan
        }
    }
}

// std::error::Error trait implementasyonu no_std ortamında std feature gerektirir.
// Eğer std feature yoksa bu kısım koşullu derlenmelidir.
// #[cfg(feature = "std")]
// impl std::error::Error for AssemblerError {}


pub struct SparcAssembler {
    standard_library: StandardLibrary, // StandardLibrary örneğini tut
    // Sembol tablosu gibi durumlar buraya eklenebilir:
    // label_addresses: alloc::collections::HashMap::new(),
}

impl SparcAssembler {
    /// Yeni bir SPARC assembler örneği oluşturur.
    /// StandardLibrary instance'ını dışarıdan alır.
    pub fn new(standard_library: StandardLibrary) -> Self { // StandardLibrary'yi alacak şekilde güncellendi
        SparcAssembler {
             standard_library, // StandardLibrary'yi kullan
             // Diğer alanları başlat...
        }
    }

    /// Verilen SPARC assembly kodunu derler.
    pub fn assemble(&self, assembly_code: &str) -> Result<Vec<u8>, AssemblerError> { // Return type changed
        self.standard_library.print_string("SPARC assembly kodu derleniyor...\n"); // Çıktı için StandardLibrary kullan
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        // Etiketler ve ileri referanslar için iki geçişli bir yaklaşım gerekebilir.
        // Bu örnek tek geçişlidir ve etiketleri desteklemez.

        for line_num, line in lines.enumerate() {
             let line = line.trim(); // Satır başı ve sonundaki boşlukları temizle
             if line.is_empty() || line.starts_with("!") || line.starts_with(";") || line.starts_with("#") {
                 // Boş satırları ve yorumları atla (!, ;, # ile başlayan satırlar yorum olarak kabul edilir)
                 continue;
             }

             // Gerçek SPARC komutlarını ayrıştır ve makine koduna çevir.
             // Bu kısım çok basitleştirilmiştir ve gerçek assembler mantığını içermez.
             // Örnek olarak NOP ve SETHI komutlarını ele alalım.

             let parts: Vec<&str> = line.split_whitespace().collect();

             if parts.is_empty() {
                 continue; // Boş satır (boşluklardan sonra)
             }

             let instruction = parts[0].to_lowercase(); // Komutu küçük harfe çevir

             match instruction.as_str() {
                 "nop" => { // "nop" komutu örneği (Pseudo-instruction for ORI %g0, %g0, 0)
                      // ORI %g0, %g0, 0 -> Opcode: 0x2, DestReg: %g0 (0), Rs1: %g0 (0), Imm13: 0
                      // SPARC makine kodu 32 bittir. ORI instruction formatı Type 3.
                      // Format 3: op:2 | Rd:5 | op3:6 | Rs1:5 | i:1 | simm13:13
                      // ORI: op=2, op3=0b000010, i=1 (immediate), simm13
                      // ORI %g0, %g0, 0 : op=2, Rd=0, op3=0b000010, Rs1=0, i=1, simm13=0
                      let instruction_word: u32 = (0x2 << 30) | (0 << 25) | (0b000010 << 19) | (0 << 14) | (1 << 13) | 0;
                      machine_code.extend_from_slice(&instruction_word.to_be_bytes()); // SPARC big-endian
                      self.standard_library.print_string(&format!("  Satır {}: '{}' -> NOP (0x{:08X}) derlendi.\n", line_num + 1, line, instruction_word));
                 }
                 "sethi" => { // "sethi" komutu örneği (Type 2 instruction)
                      // sethi imm22, Rd
                      // Format 2: op:2 | Rd:5 | op2:3 | imm22:22
                      // SETHI: op=0, op2=0b100
                      if parts.len() != 3 {
                          return Err(AssemblerError::SyntaxError(format!("Satır {}: 'sethi' komutu için yanlış argüman sayısı. Beklenen 2, {} bulundu.", line_num + 1, arguments.len())));
                      }
                      let immediate_str = parts[1];
                      let register_str = parts[2];

                       let rd = self.parse_register(&register_str)?; // Register numarasını ayrıştır (AssemblerError döner)
                       let immediate = self.parse_immediate(&immediate_str)?; // Immediate değerini ayrıştır (AssemblerError döner)

                       // Immediate değeri 22 bit olmalı
                       if immediate < 0 || immediate > 0x3FFFFF { // 2^22 - 1
                            return Err(AssemblerError::InvalidOperand(format!("Satır {}: sethi için immediate değeri 22 bit aralığının dışında ({})", line_num + 1, immediate)));
                       }

                      // SETHI opcode oluşturma
                      let opcode_base: u32 = 0; // op field for SETHI is 0
                      let op2: u32 = 0b100; // op2 field for SETHI is 100
                      let instruction_word: u32 = (opcode_base << 30) | ((rd as u32) << 25) | (op2 << 22) | (immediate as u32 & 0x3FFFFF);
                       machine_code.extend_from_slice(&instruction_word.to_be_bytes()); // SPARC big-endian
                       self.standard_library.print_string(&format!("  Satır {}: '{}' -> SETHI (0x{:08X}) derlendi.\n", line_num + 1, line, instruction_word));
                 }
                  "call" => { // "call" komutu örneği (Type 1 instruction)
                       // call address (address bir etiket olabilir, burada sadece örnek)
                       // Format 1: op:2 | disp30:30
                       // CALL: op=0b01
                       if parts.len() != 2 {
                            return Err(AssemblerError::SyntaxError(format!("Satır {}: 'call' komutu için yanlış argüman sayısı. Beklenen 1, {} bulundu.", line_num + 1, arguments.len())));
                       }
                       let target_str = parts[1];
                       // Gerçekte burada etiket adresi çözümlenir ve PC-relative disp30 hesaplanır.
                       // Örnek olarak sabit bir displace değeri kullanalım (veya etiket çözümlemesi ekleyelim).
                       // Etiket çözümlenirse, onun adresi alınır ve mevcut PC adresine göre bir offset hesaplanır.
                       // disp30 = (target_address - current_pc) / 4 (word adreslemesi)
                       // disp30 signed olmalı.
                       // Bu örnekte sabit 0 displacement kullanalım (call 0x0 gibi davranır)
                       let displacement: i32 = 0; // Örnek displacement

                       // Displacement değeri 30 bit olmalı (signed)
                       if displacement < -(1 << 29) || displacement >= (1 << 29) {
                            return Err(AssemblerError::InvalidOperand(format!("Satır {}: call displacement değeri 30 bit aralığının dışında ({})", line_num + 1, displacement)));
                       }

                       let instruction_word: u32 = (0b01 << 30) | ((displacement as u32 >> 2) & 0x3FFFFFFF); // displacement sağa 2 bit kaydırılır (word adreslemesi)
                        machine_code.extend_from_slice(&instruction_word.to_be_bytes()); // SPARC big-endian
                        self.standard_library.print_string(&format!("  Satır {}: '{}' -> CALL (0x{:08X}) derlendi (displacement: {}).\n", line_num + 1, line, instruction_word, displacement));
                  }
                 // ... diğer SPARC komutları için case'ler buraya eklenecek ...
                 // Load/Store (Type 3: ld, ldd, ldsb, ldsba, ldsh, ldsha, ldub, lduh, lduw, st, std, stb, sth)
                 // Arithmetic/Logical (Type 3: add, addcc, sub, subcc, ... and, or, xor, ...)
                 // Branch (Type 2: ba, bn, b pos, b neg, bz, bnz, bc, bnc, bcc, bcs, bv, bnv)
                  _ => {
                     // Bilinmeyen komut mnemoniki
                     return Err(AssemblerError::UnsupportedInstruction(format!("Satır {}: '{}'", line_num + 1, instruction)));
                 }
             }
        }

         // Eğer hiçbir komut işlenmezse ama assembly kodu boş değilse (yorumlar hariç), bu bir hata olabilir.
         // Bu kontrol assemble_code içinde kalabilir veya çağrılan yerde yapılabilir.
         // Basitlik için burada tutalım.
         if machine_code.is_empty() && !assembly_code.trim().is_empty() {
             // Boş olmayan kodu işlemediysek bu genellikle syntax hatasıdır.
             return Err(AssemblerError::SyntaxError("Assembly kodu işlenemedi veya makine koduna çevrilemedi. Sözdizimini kontrol edin.".to_string()));
         }


        self.standard_library.print_string(&format!("SPARC assembly derleme işlemi başarıyla tamamlandı. Toplam {} bayt makine kodu üretildi.\n", machine_code.len())); // Çıktı için StandardLibrary kullan
        Ok(machine_code) // Başarılı sonuç dön
    }

    /// Dosyadaki SPARC assembly kodunu okuyup derler.
    /// Sahne64 resource modülünü dosya okuma için kullanır.
    pub fn assemble_from_file(&self, input_filename: &str) -> Result<Vec<u8>, AssemblerError> { // Return type changed
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // fs::O_RDONLY yerine resource::MODE_READ kullan
        match resource::acquire(input_filename, resource::MODE_READ) {
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
                     // return Err(e.into());
                }

                // Okunan byte'ları UTF-8 string'e çevir
                match String::from_utf8(buffer) {
                    Ok(assembly_code) => {
                         // self.assemble AssemblerError döndürecek şekilde güncellendi
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

    /// Üretilen makine kodunu bir dosyaya yazar.
    /// Sahne64 resource modülünü dosya yazma için kullanır.
    pub fn write_machine_code_to_file(&self, output_filename: &str, machine_code: &[u8]) -> Result<(), AssemblerError> { // Return type changed
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // Bayrakları güncelle: fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC
        // resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE kullan
        match resource::acquire(output_filename, resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE) {
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

    fn parse_register(&self, register_str: &str) -> Result<u8, AssemblerError> { // Return type changed
         let register_str = register_str.trim(); // Trim whitespace
        // Basit register ayrıştırma fonksiyonu (örneğin %g0, %o0, %l0, %i0 - %g0-%g7, %o0-%o7, %l0-%l7, %i0-%i7)
        // SPARC registerları: %g0-%g7 (0-7), %o0-%o7 (8-15), %l0-%l7 (16-23), %i0-%i7 (24-31)
        if register_str.starts_with("%g") {
             if let Ok(reg_num) = register_str[2..].parse::<u8>() {
                 if reg_num < 8 { return Ok(reg_num); }
             }
         } else if register_str.starts_with("%o") {
              if let Ok(reg_num) = register_str[2..].parse::<u8>() {
                 if reg_num < 8 { return Ok(8 + reg_num); } // %o0 -> 8, %o7 -> 15
             }
         } else if register_str.starts_with("%l") {
              if let Ok(reg_num) = register_str[2..].parse::<u8>() {
                 if reg_num < 8 { return Ok(16 + reg_num); } // %l0 -> 16, %l7 -> 23
             }
         } else if register_str.starts_with("%i") {
              if let Ok(reg_num) = register_str[2..].parse::<u8>() {
                 if reg_num < 8 { return Ok(24 + reg_num); } // %i0 -> 24, %i7 -> 31
             }
        } else {
            // %sp, %fp gibi özel isimler veya %r0 - %r31 formatı da olabilir.
             match register_str {
                 "%sp" => return Ok(14), // %o6
                 "%fp" => return Ok(30), // %i6
                 _ => { /* Try %r format if needed */ }
             }
         }

         // Geçersiz format veya numara
        Err(AssemblerError::InvalidOperand(format!("Geçersiz register formatı veya numarası: {}", register_str)))
    }

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

    // Diğer SPARC assembly işleme fonksiyonları... (örneğin sembol tablosu yönetimi, yeniden konumlandırma vb.)
}
