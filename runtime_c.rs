use std::process::{Command, Output};
use std::io::{Error, ErrorKind};

pub struct CRuntime;

impl CRuntime {
    pub fn run(&self, executable_file: &str) -> Result<(), Error> {
        println!("Çalıştırılıyor: {}", executable_file);

        let output_result = Command::new(executable_file)
            .output(); // Çalıştırma çıktısını yakala

        match output_result {
            Ok(output) => {
                if output.status.success() {
                    println!("Yürütme başarılı.");
                    Ok(())
                } else {
                    let error_message = format!(
                        "Yürütme başarısız oldu. \nÇıkış Kodu: {:?}\nStandart Hata (Stderr):\n{}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stderr) // Stderr'ı yakala ve String'e dönüştür
                    );
                    eprintln!("{}", error_message); // Hata mesajını stderr'e yazdır
                    Err(Error::new(ErrorKind::Other, error_message))
                }
            }
            Err(e) => {
                let error_message = format!("Yürütülebilir dosya çalıştırılamadı: {}", e);
                eprintln!("{}", error_message); // Çalıştırma hatasını stderr'e yazdır
                Err(Error::new(ErrorKind::Other, error_message))
            }
        }
    }
}