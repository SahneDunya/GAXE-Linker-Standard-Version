use std::process::{Command, Stdio};
use std::error::Error;
use crate::gaxe_format::Architecture; // gaxe_format.rs'den Architecture'ı içe aktar

pub struct KotlinCompiler {
    architecture: Architecture, // Hedef mimariyi ekle
}

impl KotlinCompiler {
    pub fn new(architecture: Architecture) -> Self {
        KotlinCompiler {
            architecture,
        }
    }

    pub fn compile(&self, source_file: &str, output_file: &str) -> Result<(), Box<dyn Error>> { // Daha genel hata türü kullan
        println!("Kotlin kodu derleniyor: {} -> {} (Mimari: {:?})", source_file, output_file, self.architecture);

        // `kotlinc` komutunu mimariye özgü parametrelerle yapılandırabilirsiniz, eğer gerekliyse.
        // Şu anda kotlinc, JAR dosyaları veya JVM bytecode üretecektir.
        // GAXE yürütülebilir dosyası oluşturma süreci daha sonra ayrı bir adımda ele alınmalıdır.

        let output = Command::new("kotlinc")
            .arg(source_file)
            .arg("-include-runtime")
            .arg("-d")
            .arg(output_file)
            .stderr(Stdio::piped()) // Standart hata çıktısını yakala
            .stdout(Stdio::piped()) // Standart çıktıyı da yakalayabiliriz, eğer istersek
            .spawn()?; // spawn kullanarak komutu çalıştır ve kontrolü hemen geri al

        let process_output = output.wait_with_output()?; // İşlemin tamamlanmasını bekle ve çıktıyı al

        if process_output.status.success() {
            println!("Kotlin derlemesi başarılı.");
            // **ÖNEMLİ ADIM: JAR dosyasını GAXE dosyasına dönüştürme mantığı buraya gelecek**
            // Şu anki `kotlinc` komutu JAR dosyası üretiyor.
            // GAXE yürütülebilir dosyası oluşturmak için, JAR dosyasını okuyup, içeriğini
            // `gaxe_format::GaxeFile` yapısına uygun şekilde düzenlemeniz gerekecek.
            // Bu, ayrı bir fonksiyon veya modül içinde implemente edilebilir.
            // Örneğin: `self.create_gaxe_executable(output_file)?;` gibi bir fonksiyon çağrısı.

            Ok(())
        } else {
            let error_message = String::from_utf8(process_output.stderr)?; // Standart hatayı al
            let stdout_message = String::from_utf8(process_output.stdout)?; // Standart çıktıyı da alabiliriz

            eprintln!("Kotlin derleme hatası:");
            eprintln!("Standart Çıktı:\n{}", stdout_message); // Standart çıktıyı yazdır
            eprintln!("Standart Hata:\n{}", error_message);   // Standart hatayı yazdır

            Err(From::from(format!("Kotlin derlemesi başarısız oldu. Hata mesajı:\n{}", error_message))) // Daha detaylı hata mesajı
        }
    }
}