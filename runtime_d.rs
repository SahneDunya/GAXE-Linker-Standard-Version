use std::process::{Command, ExitStatus};
use std::io::{self, Error, ErrorKind};

pub struct DRuntime;

impl DRuntime {
    pub fn run(&self, executable_file: &str) -> Result<(), Error> {
        println!("Çalıştırılıyor: {}", executable_file); // Kullanıcıya geri bildirim ekle

        let status_result = Command::new(executable_file).status();

        match status_result {
            Ok(status) => {
                if status.success() {
                    println!("'{}' başarıyla çalıştı.", executable_file); // Başarı mesajı eklendi
                    Ok(())
                } else {
                    Self::handle_non_success_status(executable_file, status) // Hata işleme fonksiyonu
                }
            }
            Err(error) => {
                // Komut başlatılamazsa (dosya bulunamadı, izin hatası vb.)
                Err(Error::new(
                    ErrorKind::NotFound, // Daha uygun hata türü
                    format!("Yürütülebilir dosya başlatılamadı: '{}'. Hata: {}", executable_file, error),
                ))
            }
        }
    }

    fn handle_non_success_status(executable_file: &str, status: ExitStatus) -> Result<(), Error> {
        let error_message = match status.code() {
            Some(code) => {
                format!(
                    "'{}' yürütülebilir dosyası başarısız oldu. Çıkış kodu: {}",
                    executable_file, code
                )
            }
            None => {
                format!(
                    "'{}' yürütülebilir dosyası bir sinyal ile sonlandırıldı (çıkış kodu yok).",
                    executable_file
                )
            }
        };

        eprintln!("HATA: {}", error_message); // Hata mesajını stderr'e yazdır
        Err(Error::new(ErrorKind::Other, error_message)) // Daha açıklayıcı hata mesajı
    }
}