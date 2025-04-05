use std::process::Command;
use std::io::{Error, ErrorKind};

pub struct DCompiler;

impl DCompiler {
    pub fn compile(&self, source_file: &str) -> Result<(), Error> {
        let output_file = "GAXE"; // Sabit çıktı dosya adı olarak "GAXE" kullanılıyor
        println!("D dosyası derleniyor: {} -> {}", source_file, output_file); // Daha bilgilendirici çıktı

        let status = Command::new("dmd") // 'dmd' komutu PATH ortam değişkeninde varsayılıyor
            .arg(source_file)
            .arg("-of") // Çıktı dosyasını belirtmek için flag
            .arg(output_file)
            .status()?;

        if status.success() {
            println!("D derlemesi başarılı."); // Başarı mesajı eklendi
            Ok(())
        } else {
            // Daha detaylı hata bilgisi için ErrorKind::Other kullanılıyor ve hata mesajı formatlanıyor.
            Err(Error::new(
                ErrorKind::Other,
                format!("D derlemesi başarısız oldu. Hata kodu: {:?}", status.code()),
            ))
        }
    }
}