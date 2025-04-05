use std::process::{Command, Stdio};
use std::io::{Error, ErrorKind};
use std::path::Path;

pub struct RustCompiler {
    // Compiler yolu yapılandırılabilir hale getirilebilir. Şimdilik sabit bırakalım.
    compiler_path: String,
    target_architecture: Option<String>, // Hedef mimariyi yapılandırılabilir yapalım
    optimization_level: Option<String>, // Optimizasyon seviyesini yapılandırılabilir yapalım
    debug_build: bool,               // Debug/Release build seçeneği
}

impl RustCompiler {
    pub fn new() -> Self {
        RustCompiler {
            compiler_path: "rustc".to_string(), // Varsayılan rustc yolu
            target_architecture: None,           // Varsayılan olarak sistem mimarisi
            optimization_level: None,           // Varsayılan optimizasyon seviyesi
            debug_build: true,                 // Varsayılan olarak debug build
        }
    }

    // Yapılandırıcı fonksiyonlar (builder pattern)
    pub fn target_architecture(mut self, architecture: &str) -> Self {
        self.target_architecture = Some(architecture.to_string());
        self
    }

    pub fn optimization_level(mut self, level: &str) -> Self {
        self.optimization_level = Some(level.to_string());
        self
    }

    pub fn release_build(mut self, release: bool) -> Self {
        self.debug_build = !release; // debug_build true ise debug, false ise release
        self
    }


    pub fn compile(&self, source_file: &str, output_file: &str) -> Result<(), Error> {
        let source_path = Path::new(source_file);
        let output_path = Path::new(output_file);

        if !source_path.exists() {
            return Err(Error::new(ErrorKind::NotFound, format!("Kaynak dosyası bulunamadı: {}", source_file)));
        }

        println!("Rust derlemesi başlatılıyor: Kaynak = '{}', Çıktı = '{}'", source_file, output_file);

        let mut command = Command::new(&self.compiler_path);
        command.arg(source_file)
               .arg("-o")
               .arg(output_file)
               .stdout(Stdio::piped()) // Standart çıktıyı yakala
               .stderr(Stdio::piped()); // Standart hatayı yakala

        // Hedef mimariyi ayarla
        if let Some(arch) = &self.target_architecture {
            command.arg("--target").arg(arch);
            println!("Hedef mimari ayarlandı: {}", arch);
        }

        // Optimizasyon seviyesini ayarla
        if let Some(level) = &self.optimization_level {
            match level.as_str() {
                "0" => {} // -C opt-level=0 (zaten varsayılan)
                "1" => { command.args(&["-C", "opt-level=1"]); },
                "2" => { command.args(&["-C", "opt-level=2"]); },
                "3" => { command.args(&["-C", "opt-level=3"]); },
                "s" => { command.args(&["-C", "opt-level=s"]); },
                "z" => { command.args(&["-C", "opt-level=z"]); },
                _ => {
                    eprintln!("Uyarı: Geçersiz optimizasyon seviyesi: '{}'. Varsayılan seviye kullanılacak.", level);
                }
            }
            println!("Optimizasyon seviyesi ayarlandı: {}", level);
        }

        // Debug/Release build ayarla
        if !self.debug_build {
            command.arg("--release");
            println!("Release build ayarlandı.");
        } else {
            println!("Debug build ayarlandı.");
        }


        let child = command.spawn()?;
        let output = child.wait_with_output()?;


        if output.status.success() {
            println!("Rust derlemesi başarıyla tamamlandı. Çıktı dosyası: '{}'", output_file);
            Ok(())
        } else {
            let error_message = String::from_utf8_lossy(&output.stderr).trim();
            let stdout_message = String::from_utf8_lossy(&output.stdout).trim(); // Standart çıktıyı da alalım

            eprintln!("Rust derlemesi başarısız oldu. Hata mesajı:\n{}", error_message);
            if !stdout_message.is_empty() { // Standart çıktı da varsa yazdıralım (bazı durumlarda uyarılar stdout'a gidebilir)
                eprintln!("Standart Çıktı:\n{}", stdout_message);
            }

            Err(Error::new(
                ErrorKind::Other,
                format!("Rust derlemesi başarısız oldu. Detaylar için hata mesajına bakın."),
            ))
        }
    }
}