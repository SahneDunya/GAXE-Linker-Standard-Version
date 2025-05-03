// std::collections::HashMap yerine alloc koleksiyonlarını kullanabiliriz no_std ortamında
use alloc::collections::HashMap;
// Sahne64 resource modülünü içeri aktar (dosya/kaynak işlemleri için)
// Kendi crate'inizdeki yola göre ayarlayın (örn: crate::resource veya super::resource)
use crate::resource;
use crate::SahneError; // Sahne64 hata türü
use crate::Handle; // Sahne64 kaynak tanıtıcısı

use alloc::string::{String, ToString}; // String ve ToString trait'i için
use alloc::vec::Vec; // Vec için
use alloc::format; // format! makrosu için

use core::str::as_bytes;
use core::fmt;


pub struct MipsAssembler {
    label_addresses: HashMap<String, u32>,
    // MipsAssembler'ın çıktı alması gerekiyorsa StandardLibrary'yi de tutmalı
    // StandardLibrary, console Handle'ını veya messaging Handle'ını Sahne64'ten alır.
     standard_library: StandardLibrary, // Opsiyonel: Çıktı alma için
}

// MIPS Assembler özel hata türleri
#[derive(Debug)]
pub enum AssemblerError {
    SyntaxError(String),
    UnsupportedInstruction(String),
    UndefinedSymbol(String),
    EncodingError(String), // UTF-8 veya başka kodlama hatası
    IOError(SahneError), // Sahne64 kaynaklı IO hataları
    // Diğer olası derleyici hataları...
}

// SahneError'dan AssemblerError'a dönüşüm
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
            AssemblerError::UnsupportedInstruction(instruction) => write!(f, "Desteklenmeyen Komut: {}", instruction),
            AssemblerError::UndefinedSymbol(symbol) => write!(f, "Tanımsız Sembol: {}", symbol),
            AssemblerError::EncodingError(msg) => write!(f, "Kodlama Hatası: {}", msg),
            AssemblerError::IOError(e) => write!(f, "IO Hatası: {:?}", e), // SahneError'ın Debug çıktısını kullan
        }
    }
}

// std::error::Error trait implementasyonu no_std ortamında std feature gerektirir.
// Eğer std feature yoksa bu kısım koşullu derlenmelidir.
 #[cfg(feature = "std")]
 impl std::error::Error for AssemblerError {}


impl MipsAssembler {
    pub fn new(/* standard_library: StandardLibrary */) -> Self {
        MipsAssembler {
            label_addresses: HashMap::new(),
            // standard_library, // StandardLibrary ataması
        }
    }

    pub fn assemble(&mut self, assembly_code: &str) -> Result<Vec<u8>, AssemblerError> {
        // İkinci geçişte etiket adresleri gerekli olacağı için
        // assemble fonksiyonu iki geçişli mantığı kendi içinde barındırmalı.
        // Ya da new fonksiyonu compile zamanında çağrılarak etiketler toplanmalı
        // ve assemble tek geçişli olmalı (bu daha tipik bir assembler patterni değil).
        // Veya assemble_from_file içindeki read_file_to_string çağrısından sonra
        // ilk geçiş assemble içinde yapılmalı.
        // Mevcut koddaki gibi iki geçişi tek fonksiyonda yapalım, ama PC takibini düzeltelim.

        let mut machine_code = Vec::new();
        let lines: Vec<&str> = assembly_code.lines().collect();
        self.label_addresses.clear(); // Her assemble çağrısında etiketleri temizle

        let mut current_address: u32 = 0; // Program sayacı simülasyonu

        // Birinci geçiş: Etiket adreslerini topla
        for line in &lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() { continue; }

            if line.ends_with(':') {
                let label = line.trim_end_matches(':').to_string();
                if self.label_addresses.contains_key(&label) {
                     // Tekrar eden etiket hatası
                     return Err(AssemblerError::SyntaxError(format!("Tekrar eden etiket: {}", label)));
                }
                self.label_addresses.insert(label, current_address);
            } else {
                // Yönergenin uzunluğunu belirle (MIPS genellikle 4 byte)
                // Gerçek assembler'da komutun türüne göre uzunluk değişebilir (.word, .byte, string vs.)
                // Şimdilik tüm talimatlar 4 byte varsayalım.
                current_address += 4;
            }
        }

        // İkinci geçiş: Makine kodunu oluştur
         current_address = 0; // PC'yi sıfırla
        for line in &lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.ends_with(':') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
             // parts boş olamaz çünkü yukarıda kontrol edildi
            let instruction_mnemonic = parts[0].to_lowercase();
            let arguments = &parts[1..];

             // Yönergeyi işle
            match instruction_mnemonic.as_str() {
                "add" => {
                    // R-tipi talimatı: add rd, rs, rt
                    if arguments.len() != 3 {
                        return Err(AssemblerError::SyntaxError(format!("Yanlış argüman sayısı '{}' talimatı için: beklenen 3, {} bulundu.", instruction_mnemonic, arguments.len())));
                    }
                    let rd = self.register_to_binary(arguments[0])?;
                    let rs = self.register_to_binary(arguments[1])?;
                    let rt = self.register_to_binary(arguments[2])?;
                    let opcode = 0b000000; // özel kodu
                    let funct = 0b100000;  // işlev kodu for add
                    let shamt = 0b00000;    // shift miktar, add için 0
                    let instruction_binary: u32 = (opcode << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct;
                    machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                },
                "addi" => {
                    // I-tipi talimatı: addi rt, rs, immediate
                    if arguments.len() != 3 {
                        return Err(AssemblerError::SyntaxError(format!("Yanlış argüman sayısı '{}' talimatı için: beklenen 3, {} bulundu.", instruction_mnemonic, arguments.len())));
                    }
                    let rt = self.register_to_binary(arguments[0])?;
                    let rs = self.register_to_binary(arguments[1])?;
                    let immediate = arguments[2].parse::<i16>().map_err(|e| AssemblerError::SyntaxError(format!("Geçersiz hemen değer '{}': {}", arguments[2], e)))?;
                    let opcode = 0b001000; // opcode for addi
                    let instruction_binary: u32 = (opcode << 26) | (rs << 21) | (rt << 16) | (immediate as u16 as u32);
                    machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                },
                 "lw" => {
                    // I-tipi talimatı: lw rt, offset(rs)
                    if arguments.len() != 2 {
                        return Err(AssemblerError::SyntaxError(format!("Yanlış argüman sayısı '{}' talimatı için: beklenen 2, {} bulundu.", instruction_mnemonic, arguments.len())));
                    }
                    let rt = self.register_to_binary(arguments[0])?;
                    let offset_parts: Vec<&str> = arguments[1].split('(').collect();
                    if offset_parts.len() != 2 || !offset_parts[1].ends_with(')') {
                        return Err(AssemblerError::SyntaxError(format!("Geçersiz bellek ofseti formatı: {}", arguments[1])));
                    }
                    let offset = offset_parts[0].parse::<i16>().map_err(|e| AssemblerError::SyntaxError(format!("Geçersiz ofset değeri '{}': {}", offset_parts[0], e)))?;
                    let rs_arg = offset_parts[1].trim_end_matches(')');
                    let rs = self.register_to_binary(rs_arg)?;
                    let opcode = 0b100011; // opcode for lw
                    let instruction_binary: u32 = (opcode << 26) | (rs << 21) | (rt << 16) | (offset as u16 as u32);
                    machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                },
                 "sw" => {
                    // I-tipi talimatı: sw rt, offset(rs)
                    if arguments.len() != 2 {
                        return Err(AssemblerError::SyntaxError(format!("Yanlış argüman sayısı '{}' talimatı için: beklenen 2, {} bulundu.", instruction_mnemonic, arguments.len())));
                    }
                    let rt = self.register_to_binary(arguments[0])?;
                    let offset_parts: Vec<&str> = arguments[1].split('(').collect();
                     if offset_parts.len() != 2 || !offset_parts[1].ends_with(')') {
                        return Err(AssemblerError::SyntaxError(format!("Geçersiz bellek ofseti formatı: {}", arguments[1])));
                    }
                    let offset = offset_parts[0].parse::<i16>().map_err(|e| AssemblerError::SyntaxError(format!("Geçersiz ofset değeri '{}': {}", offset_parts[0], e)))?;
                    let rs_arg = offset_parts[1].trim_end_matches(')');
                    let rs = self.register_to_binary(rs_arg)?;
                    let opcode = 0b101011; // opcode for sw
                    let instruction_binary: u32 = (opcode << 26) | (rs << 21) | (rt << 16) | (offset as u16 as u32);
                    machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                },
                "j" => {
                    // J-tipi talimatı: j target_label
                    if arguments.len() != 1 {
                        return Err(AssemblerError::SyntaxError(format!("Yanlış argüman sayısı '{}' talimatı için: beklenen 1, {} bulundu.", instruction_mnemonic, arguments.len())));
                    }
                    let label = arguments[0];
                    let label_address = self.label_addresses.get(label).ok_or_else(|| AssemblerError::UndefinedSymbol(label.to_string()))?;
                    // Hedef adres, kelime adreslemesi olduğu için 4'e bölünür
                    let target_address = label_address / 4;
                    let opcode = 0b000010; // opcode for j
                    // 26-bit hedef adres
                    let instruction_binary: u32 = (opcode << 26) | (target_address & 0x3FFFFFF); // 26-bit maske uygula
                    machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                },
                 "syscall" => {
                     // R-tipi talimatı: syscall (funct=0b001100)
                     // Argümanları registerlardan alınacak (a0-a3)
                     if arguments.len() != 0 {
                         return Err(AssemblerError::SyntaxError(format!("Yanlış argüman sayısı 'syscall' talimatı için: beklenen 0, {} bulundu.", arguments.len())));
                     }
                     let opcode = 0b000000; // özel kodu
                     let funct = 0b001100; // işlev kodu for syscall
                     let rs = 0b00000; // kullanılmaz
                     let rt = 0b00000; // kullanılmaz
                     let rd = 0b00000; // kullanılmaz
                     let shamt = 0b00000; // kullanılmaz
                     let instruction_binary: u32 = (opcode << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct;
                     machine_code.extend_from_slice(&instruction_binary.to_be_bytes());
                 }
                _ => {
                    return Err(AssemblerError::UnsupportedInstruction(instruction_mnemonic.to_string()));
                }
            }
             // PC'yi ilerlet (ikinci geçişte PC'yi takip etmek gerekmez, sadece makine kodu uzunluğunu hesaplarız)
              current_address += 4; // Artık makine kodu uzunluğu kullanılır
        }


         // İkinci geçiş tamamlandı. Makine kodu boyutu, etiket hesaplamasıyla tutarlı olmalı.
         if machine_code.len() as u32 != current_address {
              // Bu bir hata olabilir veya .data section'ları gibi durumlar ele alınmalıdır.
              // Basitlik için bu kontrolü atlıyoruz veya özel bir hata dönüyoruz.
               eprintln!("Uyarı: Etiket hesaplama boyutu ({}) ile üretilen kod boyutu ({}) uyuşmuyor.", current_address, machine_code.len());
         }


        Ok(machine_code)
    }

    fn register_to_binary(&self, register: &str) -> Result<u32, AssemblerError> {
         let register = register.trim_start_matches('$'); // '$' işaretini kaldır
         let reg_num = match register {
            "zero" | "0" => 0,
            "at" | "1" => 1,
            "v0" | "2" => 2,
            "v1" | "3" => 3,
            "a0" | "4" => 4,
            "a1" | "5" => 5,
            "a2" | "6" => 6,
            "a3" | "7" => 7,
            "t0" | "8" => 8,
            "t1" | "9" => 9,
            "t2" | "10" => 10,
            "t3" | "11" => 11,
            "t4" | "12" => 12,
            "t5" | "13" => 13,
            "t6" | "14" => 14,
            "t7" | "15" => 15,
            "s0" | "16" | "fp" => 16, // $fp genellikle $s0 (16) veya $s8 (30) olabilir
            "s1" | "17" => 17,
            "s2" | "18" => 18,
            "s3" | "19" => 19,
            "s4" | "20" => 20,
            "s5" | "21" => 21,
            "s6" | "22" => 22,
            "s7" | "23" => 23,
            "t8" | "24" => 24,
            "t9" | "25" => 25,
            "k0" | "26" => 26,
            "k1" | "27" => 27,
            "gp" | "28" => 28,
            "sp" | "29" => 29,
            "s8" | "30" | "fp" => 30, // MIPS32'de $s8 genellikle $fp
            "ra" | "31" => 31,
            _ => return Err(AssemblerError::SyntaxError(format!("Geçersiz register: {}", register))),
         };
         Ok(reg_num)
    }


    // Assembly kodunu bir dosyadan okuyarak derleme fonksiyonu
    pub fn assemble_from_file(&mut self, file_path: &str) -> Result<Vec<u8>, AssemblerError> {
        // read_file_to_string fonksiyonu Sahne64'ü kullanacak
        match self.read_file_to_string(file_path) {
            Ok(assembly_code) => {
                 // Dosyadan okunan kodu assemble et
                 self.assemble(&assembly_code) // assemble fonksiyonu AssemblerError döner
            },
            Err(e) => Err(e.into()), // read_file_to_string'den gelen SahneError'ı AssemblerError'a çevir
        }
    }

    // Üretilen makine kodunu bir dosyaya yazma fonksiyonu
    pub fn write_machine_code_to_file(&self, file_path: &str, machine_code: &[u8]) -> Result<(), AssemblerError> {
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // Bayrakları güncelle: fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC
        // resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE kullan
        match resource::acquire(file_path, resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE) {
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
            Err(e) => Err(e.into()), // Dosya açma hatasını propagate et (SahneError -> AssemblerError)
        }
    }

    // Dosya içeriğini string olarak okuma (Sahne64 resource kullanarak)
    // fn read_file_to_string(&self, file_path: &str) -> Result<String, SahneError> // Eski İmza
     fn read_file_to_string(&self, file_path: &str) -> Result<String, AssemblerError> { // Yeni İmza (AssemblerError döner)
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // fs::O_RDONLY yerine resource::MODE_READ kullan
        match resource::acquire(file_path, resource::MODE_READ) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024]; // Okuma için ara bellek

                // Sahne64 resource::read kullanarak dosyadan oku
                /// fs::read(fd, &mut chunk) yerine resource::read(file_handle, &mut chunk) kullan
                loop {
                    match resource::read(file_handle, &mut chunk) {
                        Ok(bytes_read) => {
                            if bytes_read == 0 { // Dosya sonuna gelindi
                                break;
                            }
                            buffer.extend_from_slice(&chunk[..bytes_read]);
                        }
                        Err(e) => {
                            // Hata oluşursa dosyayı kapat (release) ve hatayı propagate et
                            let _ = resource::release(file_handle); // Dosyayı kapatmaya çalış
                            // SahneError'ı AssemblerError'a çevir
                            return Err(e.into());
                        }
                    }
                }

                // Dosya okuma bitti, dosyayı kapat (release)
                // fs::close(fd) yerine resource::release(file_handle) kullan
                if let Err(e) = resource::release(file_handle) {
                    eprintln!("Dosya kapatma hatası (okuma): {:?}", e);
                     // Kapatma hatasını döndürmek isteyebilirsiniz
                      return Err(e.into()); // SahneError'ı AssemblerError'a çevir
                }

                // Okunan byte'ları UTF-8 string'e çevir
                match String::from_utf8(buffer) {
                    Ok(s) => Ok(s),
                    // UTF-8 hatasını AssemblerError::EncodingError'a çevir
                    Err(e) => Err(AssemblerError::EncodingError(format!("Dosya içeriği geçerli UTF-8 değil: {}", e))),
                }
            }
            // Dosya açma hatasını propagate et (SahneError -> AssemblerError)
            Err(e) => Err(e.into()),
        }
    }
}
