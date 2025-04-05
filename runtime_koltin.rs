use std::process::{Command, Stdio};
use std::io::{Error, ErrorKind};

pub struct KotlinRuntime;

impl KotlinRuntime {
    pub fn run(&self, jar_file: &str) -> Result<(), Error> {
        println!("Kotlin JAR dosyası çalıştırılıyor: {}", jar_file); // Kullanıcı geri bildirimi eklendi

        let output = Command::new("java")
            .arg("-jar")
            .arg(jar_file)
            .stderr(Stdio::piped()) // stderr'i yakala
            .output()?;

        if output.status.success() {
            println!("Kotlin JAR dosyası başarıyla çalıştı."); // Başarı mesajı eklendi
            Ok(())
        } else {
            let error_message = String::from_utf8_lossy(&output.stderr); // stderr'den hata mesajını al
            eprintln!("Kotlin çalıştırması başarısız oldu. Hata çıktısı:\n{}", error_message); // Hata mesajını stderr'e yazdır
            Err(Error::new(
                ErrorKind::Other,
                format!("Kotlin JAR çalıştırması başarısız oldu. Java komutu hatası: {}", error_message), // Daha detaylı hata mesajı
            ))
        }
    }
}