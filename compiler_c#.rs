use std::process::{Command, Stdio};
use std::io::{Error, ErrorKind};

pub struct CsharpCompiler;

impl CsharpCompiler {
    pub fn compile(&self, source_file: &str, output_file: &str) -> Result<(), Error> {
        println!("C# dosyası derleniyor: {}", source_file); // Bilgilendirici çıktı

        let output = Command::new("csc")
            .arg(source_file)
            .arg("-out:")
            .arg(output_file)
            .stderr(Stdio::piped()) // Standart hata çıktısını yakala
            .stdout(Stdio::piped()) // Standart çıktıyı da yakalayabiliriz (isteğe bağlı)
            .output()?; // `status()` yerine `output()` kullanıyoruz

        if output.status.success() {
            println!("C# derlemesi başarılı: {}", output_file); // Başarı mesajı
            Ok(())
        } else {
            // Daha detaylı hata bilgisi için stderr'i oku
            let error_message = String::from_utf8_lossy(&output.stderr);
            eprintln!("C# derleme hatası:\n{}", error_message); // Hata mesajını stderr'e yazdır

            Err(Error::new(
                ErrorKind::Other,
                format!("C# derlemesi başarısız oldu. Detaylar için stderr'e bakın."),
            ))
        }
    }
}