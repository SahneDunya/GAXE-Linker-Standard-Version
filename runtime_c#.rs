use std::process::Command;
use std::io::{self, Error, ErrorKind};
use std::fmt;

// Özel hata türü tanımlayın, bu daha spesifik hata işlemeye olanak tanır
#[derive(Debug, fmt::Display)]
pub enum CsharpRuntimeError {
    ProcessCreationFailed(io::Error), // `Command::new` başarısız olursa
    ExecutionFailed {              // `mono` yürütmesi başarısız olursa
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
    },
}

impl std::error::Error for CsharpRuntimeError {}

pub struct CsharpRuntime;

impl CsharpRuntime {
    pub fn new() -> Self {
        CsharpRuntime
    }

    pub fn run(&self, executable_file: &str) -> Result<(), CsharpRuntimeError> {
        println!("C# çalışma zamanı başlatılıyor: {}", executable_file);

        let output = Command::new("mono")
            .arg(executable_file)
            .output()
            .map_err(CsharpRuntimeError::ProcessCreationFailed)?; // süreci başlatma hatası

        if output.status.success() {
            println!("C# yürütmesi başarıyla tamamlandı: {}", executable_file);
            Ok(())
        } else {
            let error = CsharpRuntimeError::ExecutionFailed {
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            };
            eprintln!("C# çalıştırması başarısız oldu: {}", executable_file);
            eprintln!("Standart çıktı:\n{}", error.stdout);
            eprintln!("Standart hata:\n{}", error.stderr);
            Err(error)
        }
    }
}