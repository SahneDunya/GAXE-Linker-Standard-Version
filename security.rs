// GAXE format yapıları, mimari enum
use crate::gaxe_format::{Architecture, GaxeFile};

// Hash hesaplama için sha2 crate
use sha2::{Digest, Sha256};

// Sahne64 kaynak (dosya) modülü
use crate::resource;
// Sahne64 kaynak tanıtıcısı
use crate::Handle;
// Sahne64 hata türü
use super::SahneError;

// Alloc kütüphanesinden gerekli türler (Vec, String, format)
extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

// Güvenlik ile ilgili hata türü (Sahne64 hatalarını sarmalayabilir)
// Orijinal kod SahneError'ı doğrudan döndürüyordu, bu yaklaşımı koruyalım.
// Daha gelişmiş bir tasarımda SecurityError enum'ı tanımlanır ve SahneError'ı sarmalar.
 #[derive(Debug)]
 pub enum SecurityError {
     IOError(SahneError),
     HashingError(String),
     SigningError(String),
     VerificationError(String),
     FileNotFound, // specific IO error
     // ...
 }
 impl From<SahneError> for SecurityError { ... }
 impl core::fmt::Display for SecurityError { ... }
 #[cfg(feature = "std")]
 impl std::error::Error for SecurityError { ... }


pub struct Security {
    architecture: Architecture,
    // Diğer güvenlik durumları...
    // Örneğin, güvenli anahtar/sertifika yönetimi referansları
}

impl Security {
    pub fn new(architecture: Architecture) -> Self {
        Security {
            architecture,
            // Diğer güvenlik durumlarını başlat...
        }
    }

    /// Bir GAXE dosyasını belirli bir mimari için imzalar.
    /// İmzayı bir dosyaya kaydeder.
    /// Sahne64 IO hatası oluşursa Err(SahneError) döner.
    pub fn sign(&self, gaxe_file: &mut GaxeFile, private_key: &[u8]) -> Result<(), SahneError> { // Return type changed
        println!("{} mimarisi için imzalama başlatılıyor...", self.architecture);
        let result = match self.architecture {
            Architecture::RISCV => self.sign_architecture(gaxe_file, private_key, "RISC-V"),
            Architecture::X86 => self.sign_architecture(gaxe_file, private_key, "x86"),
            Architecture::ARM => self.sign_architecture(gaxe_file, private_key, "ARM"),
            Architecture::PowerPC => self.sign_architecture(gaxe_file, private_key, "PowerPC"),
            Architecture::Elbrus => self.sign_architecture(gaxe_file, private_key, "Elbrus"),
            Architecture::MIPS => self.sign_architecture(gaxe_file, private_key, "MIPS"),
            Architecture::LoongArch => self.sign_architecture(gaxe_file, private_key, "LoongArch"),
            Architecture::SPARC => self.sign_architecture(gaxe_file, private_key, "SPARC"),
            Architecture::OpenRISC => self.sign_architecture(gaxe_file, private_key, "OpenRISC"),
        };
        println!("{} mimarisi için imzalama tamamlandı.", self.architecture);
        result // Propagate the result from architecture-specific signing
    }

    /// Mimariye özgü imzalama adımları (placeholder).
    fn sign_architecture(&self, gaxe_file: &mut GaxeFile, private_key: &[u8], arch_name: &str) -> Result<(), SahneError> { // Return type changed
        println!("{} mimarisine özgü imzalama işlemleri uygulanıyor...", arch_name);
        let result = self.perform_common_signing(gaxe_file, private_key);
        println!("{} mimarisine özgü imzalama işlemleri tamamlandı.", arch_name);
        result // Propagate the result from common signing
    }

    /// Ortak imzalama adımları (hash hesaplama, imza oluşturma, dosyaya yazma).
    /// Sahne64 IO hatası oluşursa Err(SahneError) döner.
    fn perform_common_signing(&self, gaxe_file: &mut GaxeFile, private_key: &[u8]) -> Result<(), SahneError> { // Return type changed
        println!("Ortak imzalama işlemleri uygulanıyor...");

        // Hash hesaplama (SHA-256)
        let hash = self.calculate_hash(gaxe_file);
        println!("Hesaplanan Hash (SHA-256): {:x?}", hash); // Hex formatında yazdır
        println!("Kullanılan Özel Anahtar (Örnek): {:x?}", private_key); // Hex formatında yazdır

        // **GERÇEK IMZALAMA ADIMI BURAYA GELECEK**
        // Burada gerçek bir imzalama algoritması (örn. ECDSA, RSA) kullanılmalı
        // ve 'private_key' ile 'hash' kullanılarak imza oluşturulmalıdır.
        // Şimdilik placeholder olarak hash'in kendisini kullanıyoruz.
        let signature = hash.clone(); // Placeholder imza

        // İmzayı bir dosyaya Sahne64 kaynak sistemi üzerinden kaydet
        let filename = format!("{}.sig", "output.gaxe"); // Örnek dosya adı
        println!("İmzayı dosyaya yazılıyor: {}", filename);
         write_signature_to_file returns Result<(), SahneError>
        let result = self.write_signature_to_file(&filename, &signature); // Use ? if returning custom error

        println!("Ortak imzalama işlemleri tamamlandı.");
        result // Propagate the result from file writing
    }

    /// Bir GAXE dosyasının imzasını doğrular.
    /// Doğrulama başarılı olursa true, başarısız olursa false döner.
    /// Sahne64 IO hatası oluşursa Err(SahneError) döner.
    pub fn verify(&self, gaxe_file: &GaxeFile, public_key: &[u8]) -> Result<bool, SahneError> { // Return type changed
        println!("{} mimarisi için doğrulama başlatılıyor...", self.architecture);
        let result = match self.architecture {
            Architecture::RISCV => self.verify_architecture(gaxe_file, public_key, "RISC-V"),
            Architecture::X86 => self.verify_architecture(gaxe_file, public_key, "x86"),
            Architecture::ARM => self.verify_architecture(gaxe_file, public_key, "ARM"),
            Architecture::PowerPC => self.verify_architecture(gaxe_file, public_key, "PowerPC"),
            Architecture::Elbrus => self.verify_architecture(gaxe_file, public_key, "Elbrus"),
            Architecture::MIPS => self.verify_architecture(gaxe_file, public_key, "MIPS"),
            Architecture::LoongArch => self.verify_architecture(gaxe_file, public_key, "LoongArch"),
            Architecture::SPARC => self.verify_architecture(gaxe_file, public_key, "SPARC"),
            Architecture::OpenRISC => self.verify_architecture(gaxe_file, public_key, "OpenRISC"),
        };
        println!("{} mimarisi için doğrulama tamamlandı.", self.architecture);
        result // Propagate the result from architecture-specific verification
    }

    /// Mimariye özgü doğrulama adımları (placeholder).
    fn verify_architecture(&self, gaxe_file: &GaxeFile, public_key: &[u8], arch_name: &str) -> Result<bool, SahneError> { // Return type changed
        println!("{} mimarisine özgü doğrulama işlemleri uygulanıyor...", arch_name);
        let result = self.perform_common_verification(gaxe_file, public_key);
        println!("{} mimarisine özgü doğrulama işlemleri tamamlandı. Sonuç: {:?}", arch_name, result); // Result'ı yazdır
        result // Propagate the result from common verification
    }

    /// Ortak doğrulama adımları (hash hesaplama, imza okuma, doğrulama).
    /// Doğrulama sonucu (true/false) veya Sahne64 IO hatası (Err(SahneError)) döner.
    fn perform_common_verification(&self, gaxe_file: &GaxeFile, public_key: &[u8]) -> Result<bool, SahneError> { // Return type changed
        println!("Ortak doğrulama işlemleri uygulanıyor...");

        // Hash hesaplama (SHA-256)
        let calculated_hash = self.calculate_hash(gaxe_file);
        println!("Hesaplanan Hash (SHA-256): {:x?}", calculated_hash); // Hex formatında yazdır
        println!("Kullanılan Genel Anahtar (Örnek): {:x?}", public_key); // Hex formatında yazdır

        // İmzayı dosyadan Sahne64 kaynak sistemi üzerinden oku
        let filename = format!("{}.sig", "output.gaxe"); // Örnek dosya adı
        println!("İmzayı dosyadan okunuyor: {}", filename);
        // read_signature_from_file returns Result<Vec<u8>, SahneError>
        match self.read_signature_from_file(&filename) {
            Ok(stored_signature) => {
                println!("Okunan İmza: {:x?}", stored_signature); // Hex formatında yazdır
                // **GERÇEK IMZA DOĞRULAMA ADIMI BURAYA GELECEK**
                // Burada okunan imza, hesaplanan hash ve genel anahtar kullanılarak
                // gerçek bir imza doğrulama algoritması (örn. ECDSA_verify) ile doğrulanmalıdır.
                // Şimdilik placeholder olarak hash'leri karşılaştırıyoruz (gerçek bir doğrulama değil).
                if calculated_hash == stored_signature {
                    println!("İmza doğrulandı.");
                    Ok(true) // Başarılı doğrulama
                } else {
                    println!("İmza doğrulanamadı!");
                    Ok(false) // Başarısız doğrulama (dosya okuma başarılı ama imza uyuşmuyor)
                }
            }
            Err(e) => {
                eprintln!("İmza dosyasından okuma hatası: {:?}", e);
                Err(e) // Dosya okuma hatasını propagate et
            }
        }
    }

    /// GAXE dosyasının kod ve veri bölümlerinin hash'ini hesaplar.
    /// Sahne64 ile doğrudan ilgili değil, sha2 crate kullanır.
    fn calculate_hash(&self, gaxe_file: &GaxeFile) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&gaxe_file.code_section.data);
        hasher.update(&gaxe_file.data_section.data);
        hasher.finalize().to_vec()
    }

    /// İmzayı Sahne64 kaynak sistemi üzerinden dosyaya yazar.
    fn write_signature_to_file(&self, filename: &str, signature: &[u8]) -> Result<(), SahneError> {
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // Bayrakları güncelle: fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC
        // resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE kullan
        match resource::acquire(filename, resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                // Sahne64 resource::write kullanarak dosyaya yaz
                // fs::write(fd, signature) yerine resource::write(file_handle, signature) kullan
                match resource::write(file_handle, signature) {
                    Ok(bytes_written) => {
                        let close_result = resource::release(file_handle); // Dosyayı kapat

                        if bytes_written as usize != signature.len() {
                            // Yazılan byte sayısı beklenenle uyuşmuyorsa hata
                             eprintln!("Uyarı: Tüm imza dosyaya yazılamadı. Yazılan: {}, Beklenen: {}", bytes_written, signature.len());
                             // Kapatma hatası olsa bile yazma hatasını döndür
                              if let Err(e) = close_result {
                                  eprintln!("Dosya kapatma hatası (yazma sonrası uyarıda): {:?}", e);
                                  // Kapatma hatası önemliyse burada da dönebilirsiniz
                             }
                              return Err(SahneError::CommunicationError); // Veya daha iyi bir SahneError
                        }

                        // Yazma başarılı, kapatma hatasını kontrol et
                        if let Err(e) = close_result {
                           eprintln!("Dosya kapatma hatası (yazma): {:?}", e);
                            // Kapatma hatasını döndürmek isteyebilirsiniz
                            return Err(e); // SahneError döndür
                        }

                       Ok(()) // Yazma ve kapatma başarılı
                    }
                    Err(e) => {
                        // Yazma hatası oluşursa dosyayı kapat (release) ve hatayı propagate et
                        let _ = resource::release(file_handle); // Dosyayı kapatmaya çalış
                        Err(e) // SahneError döndür
                    }
                }
            }
            // Dosya açma hatasını propagate et (SahneError)
            Err(e) => Err(e), // SahneError döndür
        }
    }

    /// İmzayı Sahne64 kaynak sistemi üzerinden dosyadan okur.
    fn read_signature_from_file(&self, filename: &str) -> Result<Vec<u8>, SahneError> {
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
                            // Bellek tahsisi hatası olabilir, ancak Vec::extend_from_slice genellikle panikler.
                            // Daha sağlam kod try_reserve kullanabilir. Şimdilik panikleyebileceğini varsayalım.
                            buffer.extend_from_slice(&chunk[..bytes_read]);
                        }
                        Err(e) => {
                            // Hata oluşursa dosyayı kapat (release) ve hatayı propagate et
                            let _ = resource::release(file_handle); // Dosyayı kapatmaya çalış
                            return Err(e); // SahneError döndür
                        }
                    }
                }

                // Dosya okuma bitti, dosyayı kapat (release)
                // fs::close(fd) yerine resource::release(file_handle) kullan
                if let Err(e) = resource::release(file_handle) {
                   eprintln!("Dosya kapatma hatası (okuma): {:?}", e);
                    // Kapatma hatasını döndürmek isteyebilirsiniz
                    // return Err(e); // SahneError döndür
                }

                Ok(buffer) // Başarılı sonuç olarak buffer'ı dön
            }
            // Dosya açma hatasını propagate et (SahneError)
            Err(e) => Err(e), // SahneError döndür
        }
    }
}
