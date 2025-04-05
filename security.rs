use crate::gaxe_format::{Architecture, GaxeFile};
use sha2::{Digest, Sha256};
use super::fs;
use super::SahneError;
use core::fmt::Write as CoreWrite; // core::fmt::Write trait'ini kullan

pub struct Security {
    architecture: Architecture,
    // Diğer güvenlik durumları...
}

impl Security {
    pub fn new(architecture: Architecture) -> Self {
        Security {
            architecture,
            // Diğer güvenlik durumlarını başlat...
        }
    }

    pub fn sign(&self, gaxe_file: &mut GaxeFile, private_key: &[u8]) {
        println!("{} mimarisi için imzalama başlatılıyor...", self.architecture);
        match self.architecture {
            Architecture::RISCV => self.sign_architecture(gaxe_file, private_key, "RISC-V"),
            Architecture::X86 => self.sign_architecture(gaxe_file, private_key, "x86"),
            Architecture::ARM => self.sign_architecture(gaxe_file, private_key, "ARM"),
            Architecture::PowerPC => self.sign_architecture(gaxe_file, private_key, "PowerPC"),
            Architecture::Elbrus => self.sign_architecture(gaxe_file, private_key, "Elbrus"),
            Architecture::MIPS => self.sign_architecture(gaxe_file, private_key, "MIPS"),
            Architecture::LoongArch => self.sign_architecture(gaxe_file, private_key, "LoongArch"),
            Architecture::SPARC => self.sign_architecture(gaxe_file, private_key, "SPARC"),
            Architecture::OpenRISC => self.sign_architecture(gaxe_file, private_key, "OpenRISC"),
        }
        println!("{} mimarisi için imzalama tamamlandı.", self.architecture);
    }

    fn sign_architecture(&self, gaxe_file: &mut GaxeFile, private_key: &[u8], arch_name: &str) {
        println!("{} mimarisine özgü imzalama işlemleri uygulanıyor...", arch_name);
        self.perform_common_signing(gaxe_file, private_key);
        println!("{} mimarisine özgü imzalama işlemleri tamamlandı.", arch_name);
    }

    fn perform_common_signing(&self, gaxe_file: &mut GaxeFile, private_key: &[u8]) {
        println!("Ortak imzalama işlemleri uygulanıyor...");

        let hash = self.calculate_hash(gaxe_file);
        println!("Hesaplanan Hash (SHA-256): {:?}", hash);
        println!("Kullanılan Özel Anahtar (Örnek): {:?}", private_key);

        // **GERÇEK IMZALAMA ADIMI BURAYA GELECEK**
        // Burada gerçek bir imzalama algoritması kullanılmalı ve imza oluşturulmalıdır.
        // Şimdilik örnek bir imza oluşturuyoruz (hash'in kendisi).
        let signature = hash.clone();

        // İmzayı bir dosyaya kaydet
        let filename = format!("{}.sig", "output.gaxe"); // Örnek dosya adı
        if let Err(e) = self.write_signature_to_file(&filename, &signature) {
            eprintln!("İmza dosyasına yazma hatası: {:?}", e);
        }

        println!("Ortak imzalama işlemleri tamamlandı.");
    }

    pub fn verify(&self, gaxe_file: &GaxeFile, public_key: &[u8]) -> bool {
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
            _ => {
                println!("Desteklenmeyen mimari için doğrulama: {:?}", self.architecture);
                false
            }
        };
        println!("{} mimarisi için doğrulama tamamlandı. Sonuç: {}", self.architecture, result);
        result
    }

    fn verify_architecture(&self, gaxe_file: &GaxeFile, public_key: &[u8], arch_name: &str) -> bool {
        println!("{} mimarisine özgü doğrulama işlemleri uygulanıyor...", arch_name);
        let verification_result = self.perform_common_verification(gaxe_file, public_key);
        println!("{} mimarisine özgü doğrulama işlemleri tamamlandı. Sonuç: {}", arch_name, verification_result);
        verification_result
    }

    fn perform_common_verification(&self, gaxe_file: &GaxeFile, public_key: &[u8]) -> bool {
        println!("Ortak doğrulama işlemleri uygulanıyor...");

        let calculated_hash = self.calculate_hash(gaxe_file);
        println!("Hesaplanan Hash (SHA-256): {:?}", calculated_hash);
        println!("Kullanılan Genel Anahtar (Örnek): {:?}", public_key);

        // İmzayı dosyadan oku
        let filename = format!("{}.sig", "output.gaxe"); // Örnek dosya adı
        match self.read_signature_from_file(&filename) {
            Ok(stored_signature) => {
                println!("Okunan İmza: {:?}", stored_signature);
                // **GERÇEK IMZA DOĞRULAMA ADIMI BURAYA GELECEK**
                // Burada okunan imza, hesaplanan hash ve genel anahtar kullanılarak doğrulanmalıdır.
                // Şimdilik sadece hash'leri karşılaştırıyoruz (gerçek bir doğrulama değil).
                if calculated_hash == stored_signature {
                    println!("İmza doğrulandı.");
                    true
                } else {
                    println!("İmza doğrulanamadı!");
                    false
                }
            }
            Err(e) => {
                eprintln!("İmza dosyasından okuma hatası: {:?}", e);
                false
            }
        }
    }

    fn calculate_hash(&self, gaxe_file: &GaxeFile) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&gaxe_file.code_section.data);
        hasher.update(&gaxe_file.data_section.data);
        hasher.finalize().to_vec()
    }

    fn write_signature_to_file(&self, filename: &str, signature: &[u8]) -> Result<(), SahneError> {
        match fs::open(filename, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC) {
            Ok(fd) => {
                match fs::write(fd, signature) {
                    Ok(_) => {
                        let _ = fs::close(fd);
                        Ok(())
                    }
                    Err(e) => {
                        let _ = fs::close(fd);
                        Err(e)
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    fn read_signature_from_file(&self, filename: &str) -> Result<Vec<u8>, SahneError> {
        match fs::open(filename, fs::O_RDONLY) {
            Ok(fd) => {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match fs::read(fd, &mut chunk) {
                        Ok(bytes_read) => {
                            if bytes_read == 0 {
                                break;
                            }
                            buffer.extend_from_slice(&chunk[..bytes_read]);
                        }
                        Err(e) => {
                            let _ = fs::close(fd);
                            return Err(e);
                        }
                    }
                }
                let _ = fs::close(fd);
                Ok(buffer)
            }
            Err(e) => Err(e),
        }
    }
}