use crate::gaxe_format::Architecture;
use super::memory;
use super::SahneError;

pub struct HardwareAbstraction {
    architecture: Architecture,
    // Belki yönetilen bir bellek bloğunun başlangıç adresi tutulabilir
    managed_memory_start: Option<*mut u8>,
    managed_memory_size: usize,
}

impl HardwareAbstraction {
    pub fn new(architecture: Architecture) -> Self {
        HardwareAbstraction {
            architecture,
            managed_memory_start: None,
            managed_memory_size: 0,
        }
    }

    // Belirli bir boyutta yönetilen bir bellek bloğu ayır
    pub fn initialize_memory(&mut self, size: usize) -> Result<(), SahneError> {
        match memory::allocate(size) {
            Ok(ptr) => {
                self.managed_memory_start = Some(ptr);
                self.managed_memory_size = size;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn read_memory(&self, address: u64, size: usize) -> Vec<u8> {
        match self.managed_memory_start {
            Some(start) => {
                if address < self.managed_memory_size as u64 && (address + size as u64) <= self.managed_memory_size as u64 {
                    let ptr = unsafe { start.add(address as usize) };
                    let slice = unsafe { core::slice::from_raw_parts(ptr, size) };
                    slice.to_vec()
                } else {
                    println!("[{}] Geçersiz bellek okuma: adres=0x{:X}, boyut={}", self.architecture_name(), address, size);
                    vec![0; size]
                }
            }
            None => {
                println!("[{}] Bellek henüz başlatılmadı.", self.architecture_name());
                vec![0; size]
            }
        }
    }

    pub fn write_memory(&self, address: u64, data: &[u8]) {
        match self.managed_memory_start {
            Some(start) => {
                if address < self.managed_memory_size as u64 && (address + data.len() as u64) <= self.managed_memory_size as u64 {
                    let ptr = unsafe { start.add(address as usize) };
                    let dest = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, data.len()) };
                    dest.copy_from_slice(data);
                    println!("[{}] Bellek yazma: adres=0x{:X}, boyut={}", self.architecture_name(), address, data.len());
                } else {
                    println!("[{}] Geçersiz bellek yazma: adres=0x{:X}, boyut={}", self.architecture_name(), address, data.len());
                }
            }
            None => {
                println!("[{}] Bellek henüz başlatılmadı.", self.architecture_name());
            }
        }
    }

    fn architecture_name(&self) -> &'static str {
        match self.architecture {
            Architecture::X86 => "x86",
            Architecture::ARM => "ARM",
            Architecture::RISCV => "RISC-V",
            Architecture::OpenRISC => "OpenRISC",
            Architecture::LoongArch => "LoongArch",
            Architecture::Elbrus => "Elbrus",
            Architecture::MIPS => "MIPS",
            Architecture::SPARC => "SPARC",
            Architecture::PowerPC => "PowerPC",
        }
    }
}