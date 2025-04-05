use std::process::{Command, Output};
use std::path::Path;

pub struct JavaCompiler;

impl JavaCompiler {
    /// Verilen Java kaynak dosyasını derler ve .class dosyalarını çıktı dizinine yerleştirir.
    ///
    /// # Arguments
    /// * `source_file` - Derlenecek Java kaynak dosyasının yolu.
    /// * `output_dir` - .class dosyalarının yerleştirileceği çıktı dizini.
    ///
    /// # Errors
    ///
    /// Java derleme işlemi başarısız olursa bir `std::io::Error` döndürür.
    /// Hata, `javac` komutundan alınan stderr çıktısını içerecektir.
    pub fn compile(&self, source_file: &str, output_dir: &str) -> Result<(), std::io::Error> {
        let output_path = Path::new(output_dir);

        // Çıktı dizininin var olduğundan emin olun, yoksa oluşturun.
        if !output_path.exists() {
            std::fs::create_dir_all(output_path)?;
        }

        println!("Java dosyası derleniyor: {} -> {}", source_file, output_dir);

        let process_output = Command::new("javac")
            .arg(source_file)
            .arg("-d")
            .arg(output_dir) // .class dosyalarını belirtilen çıktı dizinine oluşturun
            .output()?; // `output()` kullanılarak tam çıktı yakalanır

        if process_output.status.success() {
            println!("Java derlemesi başarılı oldu. .class dosyaları oluşturuldu: {}", output_dir);
            Ok(())
        } else {
            // `javac` stderr'den daha ayrıntılı bir hata mesajı alın
            let error_message = String::from_utf8_lossy(&process_output.stderr);
            eprintln!("Java derleme hatası:\n{}", error_message); // stderr'e yazdır
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Java derlemesi başarısız oldu:\n{}", error_message), // Hataya stderr çıktısını ekle
            ))
        }
    }
}