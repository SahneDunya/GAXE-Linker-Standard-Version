use std::process::{Command, Stdio};
use std::error::Error;
use std::fmt;

pub struct RustRuntime;

impl RustRuntime {
    pub fn run(&self, executable_file: &str) -> Result<(), RuntimeError> {
        println!("GAXE yürütülebilir dosyası çalıştırılıyor: {}", executable_file);

        let mut command = Command::new(executable_file);

        // **İsteğe Bağlı: Çıktıyı yakalamak için standart çıktı ve hata ayarını yapılandırabiliriz.**
        // Bu, yürütme sırasında neler olduğunu görmek için faydalı olabilir.
        // command.stdout(Stdio::piped());
        // command.stderr(Stdio::piped());

        let child = command.spawn()?; // Süreci başlat

        let output = child.wait_with_output()?; // Sürecin tamamlanmasını bekle ve çıktıyı al

        if output.status.success() {
            println!("GAXE yürütülebilir dosyası başarıyla çalıştı.");
            // **İsteğe Bağlı: Standart çıktıyı burada işleyebiliriz eğer yakaladıysak.**
            // if let Some(stdout) = &output.stdout {
            //     println!("Standart Çıktı:\n{}", String::from_utf8_lossy(stdout));
            // }
            Ok(())
        } else {
            // Çalıştırma başarısız oldu, daha detaylı hata bilgisi oluştur
            let error_message = format!(
                "GAXE yürütülebilir dosyası çalıştırılırken hata oluştu: {}\nExit Kodu: {:?}",
                executable_file,
                output.status.code() // Exit kodunu al, eğer varsa
            );

            // **İsteğe Bağlı: Standart hatayı burada işleyebiliriz eğer yakaladıysak.**
            // if let Some(stderr) = &output.stderr {
            //     error_message.push_str(&format!("\nStandart Hata:\n{}", String::from_utf8_lossy(stderr)));
            // }

            eprintln!("{}", error_message); // Hata mesajını standart hataya yazdır

            Err(RuntimeError::ExecutionFailed(error_message)) // Özel hata türümüzü döndür
        }
    }
}

// Özel Hata Türü
#[derive(Debug, fmt::Display)]
pub enum RuntimeError {
    ExecutionFailed(String),
    IoError(std::io::Error), // Olası IO hataları için varyant
}

impl Error for RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RuntimeError::ExecutionFailed(_) => None, // İç kaynak yok
            RuntimeError::IoError(err) => Some(err), // Kaynak IO hatası
        }
    }
}

impl From<std::io::Error> for RuntimeError {
    fn from(err: std::io::Error) -> Self {
        RuntimeError::IoError(err)
    }
}