use std::process::Command;
use std::io::{Error, ErrorKind, Result as IoResult}; // std::io::Result ve ErrorKind içe aktarıldı

pub struct CppCompiler;

impl CppCompiler {
    pub fn compile(&self, source_file: &str, output_file: &str) -> IoResult<()> { // Daha açıklayıcı dönüş tipi
        println!("C++ dosyası derleniyor: {}", source_file); // Derleme başlangıç mesajı

        // Çıktı dosyasının her zaman "GAXE" olmasını sağla, kullanıcının belirttiği `output_file` argümanını göz ardı et
        let gaxe_output_file = "GAXE";

        let status = Command::new("g++")
            .arg(source_file)
            .arg("-o")
            .arg(gaxe_output_file) // Sabit çıktı dosyası adı: "GAXE"
            .status()?;

        if status.success() {
            println!("C++ derlemesi başarılı. Çıktı dosyası: {}", gaxe_output_file); // Başarı mesajı, sabit dosya adıyla
            Ok(())
        } else {
            let error_message = format!("C++ derlemesi başarısız oldu. Kaynak dosya: {}, Çıktı dosyası: {}. Hata kodu: {:?}",
                                        source_file, gaxe_output_file, status.code()); // Hata mesajına dosya adları ve hata kodu eklendi
            eprintln!("{}", error_message); // Hata mesajını standart hata akışına yaz
            Err(Error::new(ErrorKind::Other, error_message)) // Daha açıklayıcı hata mesajı ile hata döndür
        }
    }
}