use crate::arch_sparc::SparcArchitecture;
use crate::gaxe_format::Architecture;
use crate::hardware_abstraction::HardwareAbstraction;
use crate::standard_library::StandardLibrary;
use super::memory;
use super::SahneError;
use core::ptr;
use std::io::{self, Write};

pub struct SparcRuntime {
    architecture: SparcArchitecture,
    pc: u64,
    registers: [u64; 32],
    memory_ptr: *mut u8, // Bellek için raw pointer
    memory_size: usize,
    hal: HardwareAbstraction,
    stdlib: StandardLibrary,
    pub architecture_type: Architecture,
}

impl SparcRuntime {
    pub fn new(architecture_type: Architecture, memory_size: usize) -> Result<Self, SahneError> {
        match memory::allocate(memory_size) {
            Ok(memory_ptr) => Ok(SparcRuntime {
                architecture: SparcArchitecture::new(),
                pc: 0,
                registers: [0; 32],
                memory_ptr,
                memory_size,
                hal: HardwareAbstraction::new(architecture_type),
                stdlib: StandardLibrary::new(architecture_type),
                architecture_type,
            }),
            Err(e) => Err(e),
        }
    }

    // Belleği serbest bırakma (destructor gibi)
    impl Drop for SparcRuntime {
        fn drop(&mut self) {
            if !self.memory_ptr.is_null() {
                let _ = memory::free(self.memory_ptr, self.memory_size);
            }
        }
    }

    pub fn load_code(&mut self, code: &[u8]) {
        unsafe {
            let dest = self.memory_ptr as *mut u8;
            ptr::copy_nonoverlapping(code.as_ptr(), dest, code.len());
        }
    }

    pub fn run(&mut self) -> Result<(), String> {
        println!("[SparcRuntime] Çalışma zamanı başlatılıyor...");

        loop {
            let instruction_bytes = self.fetch_instruction()?;
            if instruction_bytes.is_empty() {
                println!("[SparcRuntime] Kod bölümünün sonuna ulaşıldı.");
                break;
            }

            let instruction = self.architecture.decode_instruction(&instruction_bytes)?;

            match self.architecture.execute_instruction(&instruction, self) {
                Ok(_) => {}
                Err(error) => {
                    eprintln!("[SparcRuntime] Yürütme hatası: {}", error);
                    return Err(format!("Yürütme hatası: {}", error));
                }
            }

            self.pc += instruction_bytes.len() as u64;
            if self.pc as usize >= self.memory_size {
                println!("[SparcRuntime] Bellek sınırının dışına çıkıldı.");
                break;
            }
        }

        println!("[SparcRuntime] Çalışma zamanı tamamlandı.");
        Ok(())
    }

    fn fetch_instruction(&self) -> Result<Vec<u8>, String> {
        let instruction_size = 4;
        let start = self.pc as usize;
        let end = start + instruction_size;

        if end > self.memory_size {
            return Ok(Vec::new());
        }

        let mut instruction_bytes = Vec::with_capacity(instruction_size);
        unsafe {
            let src = self.memory_ptr.add(start) as *const u8;
            for i in 0..instruction_size {
                instruction_bytes.push(ptr::read_volatile(src.add(i)));
            }
        }

        Ok(instruction_bytes)
    }

    pub fn read_memory(&self, address: u64, size: usize) -> Vec<u8> {
        if address as usize + size > self.memory_size {
            eprintln!("[SparcRuntime] Bellek sınırının dışına okuma girişimi! Adres: 0x{:X}, Boyut: {}", address, size);
            return Vec::new();
        }
        let mut data = Vec::with_capacity(size);
        unsafe {
            let src = self.memory_ptr.add(address as usize) as *const u8;
            for i in 0..size {
                data.push(ptr::read_volatile(src.add(i)));
            }
        }
        self.hal.read_memory(address, size) // HAL üzerinden bellek okuma (şimdilik HAL örneğini kullanıyoruz)
    }

    pub fn write_memory(&mut self, address: u64, data: &[u8]) {
        if address as usize + data.len() > self.memory_size {
            eprintln!("[SparcRuntime] Bellek sınırının dışına yazma girişimi! Adres: 0x{:X}, Boyut: {}", address, data.len());
            return;
        }
        unsafe {
            let dest = self.memory_ptr.add(address as usize) as *mut u8;
            ptr::copy_nonoverlapping(data.as_ptr(), dest, data.len());
        }
        self.hal.write_memory(address, data); // HAL üzerinden bellek yazma (şimdilik HAL örneğini kullanıyoruz)
    }

    pub fn get_register(&self, register_index: usize) -> u64 {
        if register_index < 32 {
            self.registers[register_index]
        } else {
            eprintln!("[SparcRuntime] Geçersiz register index: {}", register_index);
            0
        }
    }

    pub fn set_register(&mut self, register_index: usize, value: u64) {
        if register_index < 32 {
            self.registers[register_index] = value;
        } else {
            eprintln!("[SparcRuntime] Geçersiz register index: {}", register_index);
        }
    }

    pub fn print_string(&self, s: &str) {
        self.stdlib.print_string(s);
    }

    pub fn halt(&self) -> Result<(), String> {
        println!("[SparcRuntime] Halt talimatı çalıştırıldı. Yürütme durduruluyor.");
        Err("Halt talimatı çalıştırıldı.".to_string())
    }
}