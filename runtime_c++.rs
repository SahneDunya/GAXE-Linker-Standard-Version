use std::process::{Command, Stdio};
use std::io::{Error, ErrorKind};

pub struct CppRuntime;

impl CppRuntime {
    pub fn new() -> Self {
        CppRuntime
    }

    pub fn run(&self, executable_file: &str) -> Result<(), Error> {
        println!("C++ yürütülebilir dosyası çalıştırılıyor: {}", executable_file);

        let mut command = Command::new(executable_file);

        // İsteğe bağlı: Yürütülebilir dosyadan standart çıktı ve standart hata yakalamak için
        // command.stdout(Stdio::piped());
        // command.stderr(Stdio::piped());

        let output = command.spawn()?.wait_with_output()?;

        if output.status.success() {
            println!("C++ yürütme başarılı.");
            // İsteğe bağlı: Yürütülebilir dosyanın çıktısını işlemek için
            // let stdout = String::from_utf8_lossy(&output.stdout);
            // let stderr = String::from_utf8_lossy(&output.stderr);
            // println!("Standart Çıktı:\n{}", stdout);
            // println!("Standart Hata:\n{}", stderr);
            Ok(())
        } else {
            let exit_code = output.status.code().unwrap_or(-1); // Bilinmeyen hata için -1
            let error_message = format!("C++ yürütmesi başarısız oldu. Çıkış Kodu: {}", exit_code);
            eprintln!("HATA: {}", error_message); // Hata mesajını standart hataya yazdır

            // İsteğe bağlı: Daha detaylı hata bilgisi için standart hatayı da ekleyebiliriz
            // let stderr = String::from_utf8_lossy(&output.stderr);
            // if !stderr.is_empty() {
            //     eprintln!("C++ Standart Hata:\n{}", stderr);
            // }

            Err(Error::new(ErrorKind::Other, error_message))
        }
    }
}