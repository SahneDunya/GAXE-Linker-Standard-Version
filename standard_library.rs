use crate::gaxe_format::Architecture;
use super::fs;
use super::SahneError;
use core::str::as_bytes;

pub struct StandardLibrary {
    architecture: Architecture,
    // Diğer kütüphane durumları...
}

impl StandardLibrary {
    pub fn new(architecture: Architecture) -> Self {
        StandardLibrary {
            architecture,
            // Diğer kütüphane durumlarını başlat...
        }
    }

    pub fn print_string(&self, s: &str) {
        match self.architecture {
            Architecture::X86 => self.print_string_impl(s, "x86"),
            Architecture::ARM => self.print_string_impl(s, "ARM"),
            Architecture::RISCV => self.print_string_impl(s, "RISC-V"),
            Architecture::OpenRISC => self.print_string_impl(s, "OpenRISC"),
            Architecture::LoongArch => self.print_string_impl(s, "LoongArch"),
            Architecture::Elbrus => self.print_string_impl(s, "Elbrus"),
            Architecture::MIPS => self.print_string_impl(s, "MIPS"),
            Architecture::SPARC => self.print_string_impl(s, "SPARC"),
            Architecture::PowerPC => self.print_string_impl(s, "PowerPC"),
        }
    }

    // Ortak yazdırma işlevselliği (Sahne64'e özel)
    fn print_string_impl(&self, s: &str, arch_name: &str) {
        // Standart çıktı dosya tanımlayıcısı (genellikle 1)
        const STDOUT_FD: u64 = 1;

        let bytes = as_bytes(s);
        match fs::write(STDOUT_FD, bytes) {
            Ok(bytes_written) => {
                if bytes_written as usize != bytes.len() {
                    eprintln!("[{}] Uyarı: Tüm string yazılamadı. Yazılan: {}, Beklenen: {}", arch_name, bytes_written, bytes.len());
                }
            }
            Err(e) => {
                eprintln!("[{}] Hata: Standart çıktıya yazılamadı: {:?}", arch_name, e);
            }
        }
    }
}