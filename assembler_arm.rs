use crate::resource;
use crate::SahneError; // Sahne64 hata türü
use crate::Handle; // Sahne64 kaynak tanıtıcısı

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format; // For the format! macro

pub struct ArmAssembler;

#[derive(Debug)]
pub enum AssemblyError {
    SyntaxError(String),
    UnsupportedInstruction(String),
    IOError(SahneError), // SahneError'ı AssemblyError'a dahil et
    // ... diğer hata türleri ...
}

// SahneError'dan AssemblyError'a dönüşüm (mevcut ve doğru)
impl From<SahneError> for AssemblyError {
    fn from(err: SahneError) -> Self {
        AssemblyError::IOError(err)
    }
}

impl ArmAssembler {
    pub fn new() -> Self {
        ArmAssembler {}
    }

    pub fn assemble(&self, assembly_code: &str) -> Result<Vec<u8>, AssemblyError> {
        let mut machine_code = Vec::new();
        let lines = assembly_code.lines();

        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue; // Boş satırları ve yorumları atla
            }

            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.is_empty() {
                continue; // Boş satır (trim sonrası)
            }

            let instruction = parts[0].to_lowercase();

            // Bu kısım ARM assembly'nin detaylarına girer, Sahne64 ile doğrudan ilgili değil
            match instruction.as_str() {
                "mov" => {
                    if parts.len() != 3 {
                        return Err(AssemblyError::SyntaxError(format!("MOV komutu için yanlış argüman sayısı: {}", line)));
                    }
                    println!("MOV komutu bulundu: {}", line);
                    // Gerçek ARM MOV komut kodunu argümanlara göre hesapla
                    // Örnek placeholder code:
                    machine_code.extend_from_slice(&[0xE3, 0xA0, 0x00, 0x00]); // Örnek: MOV R0, #0
                },
                "add" => {
                    if parts.len() != 3 {
                        return Err(AssemblyError::SyntaxError(format!("ADD komutu için yanlış argüman sayısı: {}", line)));
                    }
                    println!("ADD komutu bulundu: {}", line);
                    // Gerçek ARM ADD komut kodunu argümanlara göre hesapla
                    // Örnek placeholder code:
                    machine_code.extend_from_slice(&[0xE2, 0x80, 0x00, 0x01]); // Örnek: ADD R0, R0, #1
                },
                 "sub" => {
                    if parts.len() != 3 {
                        return Err(AssemblyError::SyntaxError(format!("SUB komutu için yanlış argüman sayısı: {}", line)));
                    }
                    println!("SUB komutu bulundu: {}", line);
                     // Gerçek ARM SUB komut kodunu argümanlara göre hesapla
                    // Örnek placeholder code:
                    machine_code.extend_from_slice(&[0xE2, 0x40, 0x00, 0x01]); // Örnek: SUB R0, R0, #1
                },
                 "svc" => { // SVC (Supervisor Call) - ARM'de sistem çağrısı için kullanılır
                      // ARM SVC komutu genellikle 4 byte'tır ve argümanlar registerlarda olur.
                      // Komut içinde syscall numarasını taşıyabilir veya registerdan alınır.
                       instruction_len = 4; // SVC komutu 4 byte
                       if parts.len() >= 2 { // SVC #imm
                            // İkinci parça sayi olmalı (syscall numarasını temsil ediyor)
                            let syscall_num_str = parts[1].trim_start_matches('#');
                            match u32::from_str_radix(syscall_num_str, 10).or_else(|_| u32::from_str_radix(syscall_num_str.trim_start_matches("0x"), 16)) {
                                 Ok(syscall_num) => {
                                      println!("SVC #{} komutu bulundu", syscall_num);
                                       // SVC komutunu encode et (imm Sahne64 syscall numarası olabilir)
                                       // SVC komut formatı: op:28 cond:4 | op1:4 | Rn:4 | Rd:4 | imm24:24
                                       // svc imm: cond=always (0xE), op1=15 (0xF), Rd=0, imm24 = syscall_num
                                       let svc_instruction: u32 = 0xEF000000 | syscall_num; // Basit encode örneği
                                       machine_code.extend_from_slice(&svc_instruction.to_be_bytes()); // ARM big-endian olabilir VM'e göre ayarla
                                 },
                                 Err(_) => {
                                      return Err(AssemblyError::SyntaxError(format!("Geçersiz SVC numarası formatı: {}", parts[1])));
                                 }
                            }

                       } else {
                            // Argümansız SVC (syscall numarası R7/R8 gibi registerda olabilir)
                             println!("Argümansız SVC komutu bulundu");
                             let svc_instruction: u32 = 0xEF000000; // Argümansız SVC encode örneği
                             machine_code.extend_from_slice(&svc_instruction.to_be_bytes());
                       }
                 }
                _ => {
                    return Err(AssemblyError::UnsupportedInstruction(format!("Desteklenmeyen komut: {}", instruction)));
                }
            }
        }

        Ok(machine_code)
    }

    // Assembly kodunu bir dosyadan okuyup derleme fonksiyonu
    pub fn assemble_from_file(&self, file_path: &str) -> Result<Vec<u8>, AssemblyError> {
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // fs::O_RDONLY yerine resource::MODE_READ kullan
        match resource::acquire(file_path, resource::MODE_READ) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024]; // Okuma için ara bellek

                // Sahne64 resource::read kullanarak dosyadan oku
                // fs::read(fd, &mut chunk) yerine resource::read(file_handle, &mut chunk) kullan
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
                            return Err(e.into()); // SahneError'ı AssemblyError'a çevir
                        }
                    }
                }

                // Dosya okuma bitti, dosyayı kapat (release)
                // fs::close(fd) yerine resource::release(file_handle) kullan
                if let Err(e) = resource::release(file_handle) {
                    eprintln!("Dosya kapatma hatası (okuma): {:?}", e);
                     // Kapatma hatasını döndürmek isteyebilirsiniz
                     // return Err(e.into());
                }

                // Okunan byte'ları UTF-8 string'e çevir
                match String::from_utf8(buffer) {
                    Ok(code) => self.assemble(&code), // String'i derleme fonksiyonuna pass et
                    Err(e) => Err(AssemblyError::SyntaxError(format!("Dosya içeriği geçerli UTF-8 değil: {}", e))),
                }
            }
            Err(e) => Err(e.into()), // Dosya açma hatasını propagate et
        }
    }

    // Üretilen makine kodunu bir dosyaya yazma fonksiyonu
    pub fn write_machine_code_to_file(&self, file_path: &str, machine_code: &[u8]) -> Result<(), AssemblyError> {
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
                         if bytes_written as usize != machine_code.len() {
                             eprintln!("Uyarı: Tüm makine kodu dosyaya yazılamadı. Yazılan: {}, Beklenen: {}", bytes_written, machine_code.len());
                              // Bu bir hata olarak kabul edilebilir
                               let _ = resource::release(file_handle);
                               return Err(AssemblyError::IOError(SahneError::CommunicationError)); // Veya daha iyi bir hata
                         }
                         // Yazma başarılı, dosyayı kapat (release)
                        if let Err(e) = resource::release(file_handle) {
                            eprintln!("Dosya kapatma hatası (yazma): {:?}", e);
                             // Kapatma hatasını döndürmek isteyebilirsiniz
                             // return Err(e.into());
                        }
                        Ok(()) // Yazma ve kapatma başarılı (veya kapatma hatası yoksayılırsa)
                    }
                    Err(e) => {
                        // Yazma hatası oluşursa dosyayı kapat (release) ve hatayı propagate et
                        let _ = resource::release(file_handle); // Dosyayı kapatmaya çalış
                        Err(e.into()) // SahneError'ı AssemblyError'a çevir
                    }
                }
            }
            Err(e) => Err(e.into()), // Dosya açma hatasını propagate et
        }
    }

    // Diğer ARM assembly işleme fonksiyonları...
    // Örnek: Sembol tablosu yönetimi, ikinci pass (resolve adresler)
}
