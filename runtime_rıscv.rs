use crate::arch_riscv::RiscvArchitecture;
use crate::gaxe_format::GaxeFile; // GaxeFile yapısını içe aktar
use std::error::Error;
use std::fmt;
use super::{memory, arch, fs, SahneError}; // Sahne64 modüllerini içe aktar

// Özel Çalışma Zamanı Hata Enumu
#[derive(Debug, fmt::Display)]
pub enum RiscvRuntimeError {
    InvalidInstruction,
    MemoryAccessError(u64), // Hatalı bellek erişim adresini içerir
    SahneError(SahneError), // Sahne64 hatalarını kapsar
    // ... diğer çalışma zamanı hata türleri eklenebilir
    UnknownError(String),
}

impl From<SahneError> for RiscvRuntimeError {
    fn from(err: SahneError) -> Self {
        RiscvRuntimeError::SahneError(err)
    }
}

impl std::error::Error for RiscvRuntimeError {}

pub struct RiscvRuntime {
    architecture: RiscvArchitecture,
    memory_ptr: *mut u8, // Bellek için ham işaretçi
    memory_size: usize, // Bellek boyutu
    pc: u64,         // Program Sayacı (Program Counter)
    // Registers (örnek olarak 32 adet 64-bit register)
    registers: [u64; 32],
    // ... diğer durumlar eklenebilir (örn. CSR'ler)
}

impl RiscvRuntime {
    pub fn new(memory_size: usize) -> Result<Self, RiscvRuntimeError> {
        match memory::allocate(memory_size) {
            Ok(ptr) => Ok(RiscvRuntime {
                architecture: RiscvArchitecture::new(),
                memory_ptr: ptr,
                memory_size,
                pc: 0,
                registers: [0; 32],
            }),
            Err(e) => Err(RiscvRuntimeError::from(e)),
        }
    }

    // Belleği serbest bırakmak için Drop trait'ini uygula
    impl Drop for RiscvRuntime {
        fn drop(&mut self) {
            if !self.memory_ptr.is_null() {
                let _ = unsafe { memory::free(self.memory_ptr, self.memory_size) };
            }
        }
    }

    // GAXE dosyasını alacak şekilde 'run' fonksiyonunu güncelle
    pub fn run(&mut self, gaxe_file: &GaxeFile) -> Result<(), RiscvRuntimeError> {
        println!("RISC-V çalışma zamanı başlatılıyor...");

        // GAXE dosyasından kod bölümünü al
        let code_section = &gaxe_file.code_section;
        println!(
            "Kod bölümü yükleniyor: offset=0x{:X}, size={}",
            code_section.offset, code_section.size
        );

        // Kod bölümünü belleğe yükle
        self.load_code_to_memory(code_section)?;

        println!("Kod yürütülmeye başlanıyor. Başlangıç adresi PC=0x{:X}", self.pc);

        // Basit bir yürütme döngüsü
        loop {
            // 1. Talimatı bellekteki PC adresinden getir
            let instruction_bytes = self.fetch_instruction()?;

            // Eğer talimat getirme başarısız olursa, döngüden çık
            if instruction_bytes.is_empty() {
                println!("Kod sonuna ulaşıldı veya talimat getirilemedi. Yürütme durduruluyor.");
                break;
            }

            // 2. Talimatı çöz (decode et)
            let instruction = self.architecture.decode_instruction(&instruction_bytes)?;

            // 3. Talimatı yürüt
            match self.architecture.execute_instruction(&instruction, self) {
                Ok(_) => {
                    // Talimat başarıyla yürütüldü, PC'yi güncelle
                    self.pc += 4;
                }
                Err(error) => {
                    eprintln!("Çalışma zamanı hatası: {}", error);
                    return Err(error);
                }
            }

            // 4. Çıkış koşullarını kontrol et
            if self.pc > (code_section.offset + code_section.size) {
                println!("Kod bölümünün sonuna ulaşıldı. Yürütme durduruluyor.");
                break;
            }
            if self.pc >= self.memory_size as u64 {
                return Err(RiscvRuntimeError::MemoryAccessError(self.pc));
            }
        }

        println!("RISC-V çalışma zamanı tamamlandı.");
        Ok(()) // Başarılı yürütme
    }


    fn load_code_to_memory(&mut self, code_section: &GaxeSection) -> Result<(), RiscvRuntimeError> {
        let start_address = code_section.offset;
        let code_bytes = &code_section.data;
        let code_size = code_section.size as usize;

        if start_address as usize + code_size > self.memory_size {
            return Err(RiscvRuntimeError::MemoryAccessError(start_address)); // Bellek sınırını aşıyor
        }

        // Kodu belleğe kopyala
        unsafe {
            let dest = self.memory_ptr.add(start_address as usize);
            core::ptr::copy_nonoverlapping(code_bytes.as_ptr(), dest, code_size);
        }
        Ok(())
    }


    fn fetch_instruction(&self) -> Result<Vec<u8>, RiscvRuntimeError> {
        let instruction_size = 4;
        let current_pc = self.pc as usize;

        if current_pc + instruction_size > self.memory_size {
            return Ok(Vec::new()); // Bellek sınırının sonuna ulaşıldı veya geçildi, boş vektör dön
        }

        let instruction_bytes = unsafe {
            core::slice::from_raw_parts(self.memory_ptr.add(current_pc), instruction_size).to_vec()
        };
        Ok(instruction_bytes)
    }


    // Yardımcı bellek okuma/yazma fonksiyonları
    pub fn read_memory_byte(&self, address: u64) -> Result<u8, RiscvRuntimeError> {
        if address >= self.memory_size as u64 {
            return Err(RiscvRuntimeError::MemoryAccessError(address));
        }
        unsafe { Ok(*self.memory_ptr.add(address as usize)) }
    }

    pub fn write_memory_byte(&mut self, address: u64, value: u8) -> Result<(), RiscvRuntimeError> {
        if address >= self.memory_size as u64 {
            return Err(RiscvRuntimeError::MemoryAccessError(address));
        }
        unsafe { *self.memory_ptr.add(address as usize) = value; }
        Ok(())
    }

    pub fn read_memory_word(&self, address: u64) -> Result<u32, RiscvRuntimeError> {
        if address + 4 > self.memory_size as u64 {
            return Err(RiscvRuntimeError::MemoryAccessError(address));
        }
        unsafe {
            let ptr = self.memory_ptr.add(address as usize) as *const u32;
            Ok(*ptr) // Varsayılan olarak sistemin endian'lığını kullanır
        }
    }

    pub fn write_memory_word(&mut self, address: u64, value: u32) -> Result<(), RiscvRuntimeError> {
        if address + 4 > self.memory_size as u64 {
            return Err(RiscvRuntimeError::MemoryAccessError(address));
        }
        unsafe {
            let ptr = self.memory_ptr.add(address as usize) as *mut u32;
            *ptr = value; // Varsayılan olarak sistemin endian'lığını kullanır
        }
        Ok(())
    }

    // Sistem çağrılarını işleme (örnek olarak sadece bir "exit" syscall)
    pub fn handle_syscall(&mut self) -> Result<(), RiscvRuntimeError> {
        let syscall_number = self.registers[17]; // a7 register'ı (RISC-V calling convention)
        match syscall_number {
            93 => { // exit
                let exit_code = self.registers[10]; // a0 register'ı
                println!("Sistem çağrısı: exit, kod: {}", exit_code);
                // Burada VM'yi durdurma veya uygun bir işlem yapabilirsiniz.
                // Şimdilik sadece bir mesaj yazdırıyoruz ve döngüden çıkıyoruz.
                return Ok(()); // Çalışma zamanını sonlandır
            }
            64 => { // write (örnek olarak stdout'a yazma)
                let fd = self.registers[10]; // a0: dosya tanımlayıcısı (1 stdout)
                let addr = self.registers[11]; // a1: yazılacak verinin adresi
                let len = self.registers[12]; // a2: yazılacak veri boyutu

                if fd == 1 { // stdout
                    let bytes = self.read_memory_range(addr, len as usize)?;
                    let s = core::str::from_utf8(&bytes).map_err(|_| RiscvRuntimeError::UnknownError("UTF-8 hatası".into()))?;
                    println!("{}", s); // Rust'ın println! makrosunu kullanıyoruz (bu örnek için)
                    // Gerçek bir Sahne64 ortamında burası fs::write(1, bytes) ile değiştirilmelidir.
                    // Ancak bu örnek, VM'nin içindeki kodun nasıl bir çıktı alabileceğini göstermektedir.
                } else {
                    eprintln!("Desteklenmeyen dosya tanımlayıcısı: {}", fd);
                }
                // Sistem çağrısı dönüş değerini (genellikle yazılan byte sayısı veya hata kodu) ayarlayabilirsiniz.
                self.registers[10] = len; // Örnek olarak yazılan byte sayısını döndürüyoruz.
                Ok(())
            }
            _ => {
                eprintln!("Desteklenmeyen sistem çağrısı numarası: {}", syscall_number);
                Err(RiscvRuntimeError::UnknownError(format!("Desteklenmeyen syscall: {}", syscall_number)))
            }
        }
    }

    // Belirli bir adresten başlayarak belirli bir boyutta bellek okuma
    fn read_memory_range(&self, address: u64, size: usize) -> Result<&[u8], RiscvRuntimeError> {
        if address as usize + size > self.memory_size {
            return Err(RiscvRuntimeError::MemoryAccessError(address));
        }
        unsafe { Ok(core::slice::from_raw_parts(self.memory_ptr.add(address as usize), size)) }
    }

    // ... diğer RISC-V çalışma zamanı fonksiyonları...
}