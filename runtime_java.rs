use std::process::{Command, Stdio};
use std::io::{Error, ErrorKind, Result};

pub struct JavaRuntime;

impl JavaRuntime {
    pub fn run(&self, class_path: &str, main_class: &str) -> Result<()> {
        println!("Java uygulaması çalıştırılıyor: sınıf yolu='{}', ana sınıf='{}'", class_path, main_class);

        let output = Command::new("java")
            .arg("-cp")
            .arg(class_path)
            .arg(main_class)
            .stdout(Stdio::piped()) // Standart çıktıyı yakala
            .stderr(Stdio::piped()) // Standart hatayı yakala
            .spawn()?; // Komutu asenkron olarak başlat

        let completed_process = output.wait_with_output()?; // İşlemin tamamlanmasını bekle ve çıktıyı al

        if completed_process.status.success() {
            println!("Java uygulaması başarıyla tamamlandı.");
            if !completed_process.stdout.is_empty() {
                println!("Standart Çıktı:\n{}", String::from_utf8_lossy(&completed_process.stdout));
            }
            Ok(())
        } else {
            let error_message = format!(
                "Java çalıştırması başarısız oldu. \nStandart Hata:\n{}",
                String::from_utf8_lossy(&completed_process.stderr)
            );
            eprintln!("{}", error_message); // Standart hataya yazdır
            Err(Error::new(ErrorKind::Other, error_message)) // Daha detaylı hata mesajı döndür
        }
    }
}