use std::process::{Command, Output};
use std::io::{Error, ErrorKind, Result as IoResult};
use std::path::Path;

pub struct CCompiler {
    compiler_path: String, // Derleyici yolu yapılandırılabilir hale getirildi
    default_flags: Vec<String>, // Varsayılan derleyici bayrakları
}

impl CCompiler {
    // Yeni bir CCompiler örneği oluşturur. Derleyici yolu ve varsayılan bayraklar yapılandırılabilir.
    pub fn new(compiler_path: String, default_flags: Vec<String>) -> Self {
        CCompiler {
            compiler_path,
            default_flags,
        }
    }

    // Kaynak C dosyasını belirtilen çıktı dosyasına derler.
    pub fn compile(&self, source_file: &str, output_file: &str) -> IoResult<()> {
        // Kaynak dosyasının varlığını kontrol et
        if !Path::new(source_file).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("Kaynak dosya bulunamadı: {}", source_file),
            ));
        }

        println!("C dosyası derleniyor: {} -> {}", source_file, output_file);

        let output = Command::new(&self.compiler_path) // Yapılandırılabilir derleyici yolu kullan
            .arg(source_file)
            .arg("-o")
            .arg(output_file)
            .args(&self.default_flags) // Varsayılan bayrakları ekle
            .output()?; // `status()` yerine `output()` kullanılarak daha fazla bilgi alınır

        if output.status.success() {
            println!("C derlemesi başarılı.");
            Ok(())
        } else {
            // Hata durumunda daha detaylı hata mesajı oluştur
            let error_message = format!(
                "C derlemesi başarısız oldu. \nKomut: {} {} -o {} {}\nÇıkış Kodu: {}\nStdout: {}\nStderr: {}",
                self.compiler_path,
                source_file,
                output_file,
                self.default_flags.join(" "),
                output.status.code().unwrap_or(-1), // Çıkış kodunu al, yoksa -1
                String::from_utf8_lossy(&output.stdout), // Stdout'u stringe dönüştür
                String::from_utf8_lossy(&output.stderr)  // Stderr'ı stringe dönüştür
            );
            eprintln!("{}", error_message); // Hata mesajını stderr'e yazdır

            Err(Error::new(ErrorKind::Other, error_message))
        }
    }
}