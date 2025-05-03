use crate::resource;
use super::SahneError; // Sahne64 hata türü (varsa crate::SahneError olarak değiştirin)
use crate::Handle; // Sahne64 kaynak tanıtıcısı

use alloc::string::{String, ToString}; // String ve ToString trait'i için
use alloc::vec::Vec; // Vec için
use alloc::format; // format! makrosu için
use core::fmt; // Error Display için
use core::str::from_utf8; // from_utf8 kullanıldığı için


pub struct RiscvAssembler;

// RISC-V Assembler özel hata türleri
#[derive(Debug, PartialEq, Eq)] // fmt::Display de burada derive edilebilir
pub enum AssemblerError {
    SyntaxError(String), // Genel sözdizimi veya diğer ayrıştırma/anlamsal hatalar için detaylı mesaj
    InvalidOperand(String), // İşlenen formatı veya değeri yanlış
    UnsupportedInstruction(String), // Bilinmeyen veya desteklenmeyen komut mnemonik
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


impl RiscvAssembler {
    pub fn new() -> Self {
        RiscvAssembler {
             // Sembol tablosu gibi durumlar buraya eklenebilir:
              label_addresses: alloc::collections::HashMap::new(),
        }
    }

    /// Verilen RISC-V assembly kodunu makine koduna çevirir.
    /// Gerçek derleyici mantığı buraya yazılmalıdır.
    /// Sözdizimi, işlenen hataları vb. için Result<Vec<u8>, AssemblerError> döndürür.
    pub fn assemble(&self, assembly_code: &str) -> Result<Vec<u8>, AssemblerError> { // Return type changed
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { // Boş satırları ve yorumları atla
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue; // İşlenecek bir şey yoksa devam et
            }

            let instruction = parts[0].to_lowercase(); // Komutu küçük harfe çevir
            let arguments = &parts[1..];

            // **DİKKAT:** Bu kısım GERÇEK RISC-V assembly'e çeviri yapmaz.
            // Gerçek derleyici mantığı (parsing, semantik analiz, kod üretimi) buraya yazılmalıdır.
            // RISC-V komutları 32-bit veya 16-bit (Compressed) olabilir.
            // Bu süreçte sözdizimi, bilinmeyen komut, yanlış argüman vb. hatalar
            // AssemblerError'ın diğer varyantları olarak döndürülmelidir.

            match instruction.as_str() {
                "addi" => {
                    // addi rd, rs1, imm (I-Type)
                    if arguments.len() != 3 {
                        return Err(AssemblerError::SyntaxError(format!("addi için yanlış sayıda argüman: beklenen 3, {} bulundu.", arguments.len())));
                    }
                    let rd = self.parse_register(arguments[0])?; // parse_register artık AssemblerError döner
                    let rs1 = self.parse_register(arguments[1])?; // parse_register artık AssemblerError döner
                    let imm = self.parse_immediate(arguments[2])?; // parse_immediate artık AssemblerError döner

                    let opcode = 0b0010011; // I-tipi opcode (addi için)
                    let funct3 = 0b000;    // funct3 (addi için)

                     // Immediate değeri 12 bit olmalı
                     if imm < -2048 || imm > 2047 { // 2^11 - 1
                         return Err(AssemblerError::InvalidOperand(format!("addi için immediate değeri 12 bit aralığının dışında ({})", imm)));
                     }


                    let instruction_bytes = self.encode_i_type(opcode, funct3, funct3, imm, rs1, rd);
                    machine_code.extend_from_slice(&instruction_bytes);
                }
                "li" => {
                    // li rd, imm (pseudo-instruction, addi veya lui/addi olarak ele alınır)
                    if arguments.len() != 2 {
                        return Err(AssemblerError::SyntaxError(format!("li için yanlış sayıda argüman: beklenen 2, {} bulundu.", arguments.len())));
                    }
                    let rd = self.parse_register(arguments[0])?; // parse_register artık AssemblerError döner
                    let imm = self.parse_immediate(arguments[1])?; // parse_immediate artık AssemblerError döner

                     // li psuedo-instruction'ı işleme:
                     // Eğer imm 12 bit aralığındaysa (signed): addi rd, x0, imm
                     // Eğer imm 32 bit aralığındaysa: lui rd, %hi(imm) ; addi rd, rd, %lo(imm)
                     // Bu örnekte sadece 12 bit addi durumunu simüle ediyoruz.
                     if imm >= -2048 && imm <= 2047 {
                         // addi rd, x0, imm
                         let opcode = 0b0010011; // I-tipi opcode (addi)
                         let funct3 = 0b000;    // funct3 (addi)
                         let rs1 = 0;          // x0 register numarası (sıfır)
                         let instruction_bytes = self.encode_i_type(opcode, funct3, funct3, imm, rs1, rd);
                         machine_code.extend_from_slice(&instruction_bytes);
                     } else {
                         // Lui/addi ikilisi gerekli veya desteklenmiyor
                         return Err(AssemblerError::UnsupportedInstruction(format!("li için immediate değeri çok büyük veya karmaşık ({})", imm)));
                         // Gerçek implementasyonda burada lui ve addi komutları üretilir.
                     }

                }
                "nop" => {
                    // nop (Pseudo-instruction for ADDI x0, x0, 0)
                     let opcode = 0b0010011; // I-type
                     let funct3 = 0b000; // ADDI
                     let rd = 0; // x0
                     let rs1 = 0; // x0
                     let imm = 0;
                     let instruction_bytes = self.encode_i_type(opcode, funct3, funct3, imm, rs1, rd);
                     machine_code.extend_from_slice(&instruction_bytes);

                }
                _ => {
                    // Bilinmeyen komut mnemoniki
                    return Err(AssemblerError::UnsupportedInstruction(instruction.to_string()));
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

    fn parse_register(&self, reg_str: &str) -> Result<u8, AssemblerError> { // Return type changed
        let reg_str = reg_str.trim(); // Trim whitespace
        // ABI isimlerini de destekleyebiliriz (zero, ra, sp, gp, tp, t0-t6, s0-s11, a0-a7)
        let reg_num = match reg_str {
             "x0" | "zero" => 0,
             "x1" | "ra" => 1,
             "x2" | "sp" => 2,
             "x3" | "gp" => 3,
             "x4" | "tp" => 4,
             "x5" | "t0" => 5,
             "x6" | "t1" => 6,
             "x7" | "t2" => 7,
             "x8" | "s0" | "fp" => 8, // fp genellikle s0 veya s1
             "x9" | "s1" => 9,
             "x10" | "a0" => 10,
             "x11" | "a1" => 11,
             "x12" | "a2" => 12,
             "x13" | "a3" => 13,
             "x14" | "a4" => 14,
             "x15" | "a5" => 15,
             "x16" | "a6" => 16,
             "x17" | "a7" => 17,
             "x18" | "s2" => 18,
             "x19" | "s3" => 19,
             "x20" | "s4" => 20,
             "x21" | "s5" => 21,
             "x22" | "s6" => 22,
             "x23" | "s7" => 23,
             "x24" | "s8" => 24,
             "x25" | "s9" => 25,
             "x26" | "s10" => 26,
             "x27" | "s11" => 27,
             "x28" | "t3" => 28,
             "x29" | "t4" => 29,
             "x30" | "t5" => 30,
             "x31" | "t6" => 31,
            _ => {
                 // xN formatını ayrıştırmaya çalış
                 if reg_str.starts_with('x') && reg_str.len() > 1 {
                     if let Ok(num) = reg_str[1..].parse::<u8>() {
                         if num < 32 { return Ok(num); }
                     }
                 }
                 // Geçersiz format veya numara
                 return Err(AssemblerError::InvalidOperand(format!("Geçersiz register formatı veya numarası: {}", reg_str)));
            }
         };
         Ok(reg_num)
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


    // I-tipi komut formatını kodla (opcode, funct3, imm, rs1, rd)
    // RISC-V komutları little-endian'dır.
    fn encode_i_type(&self, opcode: u32, funct3: u32, _funct7_shamt: u32, imm: i32, rs1: u8, rd: u8) -> [u8; 4] {
        let mut instruction: u32 = 0;

         // I-tipi format: imm[11:0] | rs1[4:0] | funct3[2:0] | rd[4:0] | opcode[6:0]
         // Bütün bitler 0'dan başlar.
         let imm_u12 = imm as u32 & 0xFFF; // Immediate 12 bit (işaretli değerin son 12 biti)

        instruction |= imm_u12 << 20;     // imm[11:0] -> bit [31:20]
        instruction |= (rs1 as u32) << 15;   // rs1[4:0] -> bit [19:15]
        instruction |= (funct3 as u32) << 12; // funct3[2:0] -> bit [14:12]
        instruction |= (rd as u32) << 7;    // rd[4:0] -> bit [11:7]
        instruction |= opcode;         // opcode[6:0] -> bit [6:0]

        instruction.to_le_bytes() // Little-endian byte sırası
    }

     // Üretilen makine kodunu bir dosyaya yazma fonksiyonu
     // Sahne64 resource modülünü dosya yazma için kullanır.
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
}
