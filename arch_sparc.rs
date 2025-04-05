use crate::gaxe_format::Architecture; // Eğer gaxe_format.rs dosyasında Architecture enum'u tanımlıysa bu satır gerekli.
use super::{fs, memory, SahneError}; // Sahne64 modüllerini içe aktar
use std::fmt; // Debug trait'ini kullanmak için gerekli.
use std::error::Error; // Error trait'ini kullanmak için gerekli.

// Özel hata türü tanımla
#[derive(Debug, Clone)]
pub enum SparcError {
    InvalidInstruction, // Geçersiz komut hatası
    ExecutionFault,     // Komut yürütme hatası (örneğin, geçersiz adres)
    UnsupportedFeature, // Desteklenmeyen SPARC özelliği (eğer bazı özellikler implemente edilmediyse)
    MemoryError(SahneError), // Sahne64 bellek hatası
    IOError(SahneError),     // Sahne64 I/O hatası
    // ... Diğer SPARC'e özgü hatalar eklenebilir ...
}

impl fmt::Display for SparcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SparcError::InvalidInstruction => write!(f, "Geçersiz SPARC komutu"),
            SparcError::ExecutionFault => write!(f, "SPARC komutu yürütme hatası"),
            SparcError::UnsupportedFeature => write!(f, "Desteklenmeyen SPARC özelliği"),
            SparcError::MemoryError(e) => write!(f, "SPARC bellek hatası: {}", e),
            SparcError::IOError(e) => write!(f, "SPARC I/O hatası: {}", e),
        }
    }
}

impl Error for SparcError {}

pub struct SparcArchitecture {
    // SPARC mimarisine özgü durumlar buraya eklenebilir.
    registers: [u32; 32],
    pc: u32,
    // **Sahne64 ile entegrasyon için ek alanlar**
    memory_base: Option<*mut u8>, // Sahne64 tarafından ayrılan bellek bloğunun başlangıç adresi
    memory_size: usize,           // Bellek bloğunun boyutu
    // ... Diğer SPARC CPU durumları eklenebilir ...
}

impl SparcArchitecture {
    pub fn new(memory_size: usize) -> Result<Self, SparcError> {
        match memory::allocate(memory_size) {
            Ok(ptr) => Ok(SparcArchitecture {
                registers: [0; 32],
                pc: 0,
                memory_base: Some(ptr),
                memory_size,
            }),
            Err(e) => Err(SparcError::MemoryError(e)),
        }
    }

    // Belleğe erişim için yardımcı fonksiyonlar (Sahne64 bellek yönetimini kullanır)
    fn read_memory(&self, address: u32, size: usize) -> Result<Vec<u8>, SparcError> {
        match self.memory_base {
            Some(base) => {
                if (address as usize) + size > self.memory_size {
                    return Err(SparcError::ExecutionFault); // Bellek sınırları aşıldı
                }
                let ptr = unsafe { base.add(address as usize) };
                let data = unsafe { core::slice::from_raw_parts(ptr as *const u8, size) };
                Ok(data.to_vec())
            }
            None => Err(SparcError::ExecutionFault), // Bellek başlatılmamış
        }
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), SparcError> {
        match self.memory_base {
            Some(base) => {
                if (address as usize) + data.len() > self.memory_size {
                    return Err(SparcError::ExecutionFault); // Bellek sınırları aşıldı
                }
                let ptr = unsafe { base.add(address as usize) };
                let dest = unsafe { core::slice::from_raw_parts_mut(ptr, data.len()) };
                dest.copy_from_slice(data);
                Ok(())
            }
            None => Err(SparcError::ExecutionFault), // Bellek başlatılmamış
        }
    }

    // Standart çıktıya yazma (Sahne64 fs::write kullanır)
    pub fn write_to_stdout(&self, s: &str) -> Result<(), SparcError> {
        const STDOUT_FD: u64 = 1;
        let bytes = s.as_bytes();
        match fs::write(STDOUT_FD, bytes) {
            Ok(_) => Ok(()),
            Err(e) => Err(SparcError::IOError(e)),
        }
    }

    pub fn execute_instruction(&mut self, instruction_bytes: &[u8]) -> Result<(), SparcError> {
        let instruction = self.decode_instruction(instruction_bytes)?;
        self.execute_decoded_instruction(instruction)?;
        Ok(())
    }

    fn decode_instruction(&self, instruction_bytes: &[u8]) -> Result<SparcInstruction, SparcError> {
        if instruction_bytes.len() < 4 { // SPARC komutları genellikle 4 bayttır
            return Err(SparcError::InvalidInstruction);
        }

        let instruction_word = u32::from_be_bytes([
            instruction_bytes[0],
            instruction_bytes[1],
            instruction_bytes[2],
            instruction_bytes[3],
        ]);

        let opcode = (instruction_word >> 26) & 0x3F; // En yüksek 6 bit opcode'u verir

        println!("SPARC komutu baytları ayrıştırılıyor: {:?}, Opcode: 0x{:X}", instruction_bytes, opcode);

        match opcode {
            0b000000 => { // Örnek: SETHI (Set High bits of register)
                let rd = (instruction_word >> 21) & 0x1F;
                let imm22 = instruction_word & 0x3FFFFF;
                println!("SETHI rd={}, imm22={}", rd, imm22);
                Ok(SparcInstruction::SETHI { dest_reg: rd as u8, immediate: imm22 })
            }
            0b100000 => { // Örnek: LDUW (Load Unsigned Double Word)
                let rd = (instruction_word >> 21) & 0x1F;
                let rs1 = (instruction_word >> 14) & 0x1F;
                let simm13 = (instruction_word & 0x1FFF) as i32;
                println!("LDUW rd={}, rs1={}, simm13={}", rd, rs1, simm13);
                Ok(SparcInstruction::LDUW { dest_reg: rd as u8, src_reg1: rs1 as u8, immediate: simm13 })
            }
            _ => {
                println!("Bilinmeyen opcode: 0x{:X}", opcode);
                Err(SparcError::InvalidInstruction)
            }
        }
    }

    fn execute_decoded_instruction(&mut self, instruction: SparcInstruction) -> Result<(), SparcError> {
        match instruction {
            SparcInstruction::SETHI { dest_reg, immediate } => {
                println!("SETHI r{}, 0x{:X} yürütülüyor", dest_reg, immediate);
                if dest_reg as usize >= 32 {
                    return Err(SparcError::ExecutionFault);
                }
                self.registers[dest_reg as usize] = (immediate << 10) as u32; // SPARC'ta imm22 10 bit sola kaydırılır
                self.pc += 4;
            }
            SparcInstruction::LDUW { dest_reg, src_reg1, immediate } => {
                println!("LDUW r{}, [r{} + {}] yürütülüyor", dest_reg, src_reg1, immediate);
                if dest_reg as usize >= 32 || src_reg1 as usize >= 32 {
                    return Err(SparcError::ExecutionFault);
                }
                let address = self.registers[src_reg1 as usize].wrapping_add(immediate as u32);
                match self.read_memory(address, 4) {
                    Ok(data) => {
                        if data.len() == 4 {
                            self.registers[dest_reg as usize] = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                        } else {
                            return Err(SparcError::ExecutionFault);
                        }
                    }
                    Err(_) => return Err(SparcError::ExecutionFault),
                }
                self.pc += 4;
            }
            SparcInstruction::Nop => self.pc += 4, // NOP için de PC'yi ilerlet
            SparcInstruction::AddRegister { dest_reg, src_reg1, src_reg2 } => {
                if dest_reg as usize >= 32 || src_reg1 as usize >= 32 || src_reg2 as usize >= 32 {
                    return Err(SparcError::ExecutionFault);
                }
                let value1 = self.registers[src_reg1 as usize];
                let value2 = self.registers[src_reg2 as usize];
                self.registers[dest_reg as usize] = value1.wrapping_add(value2);
                self.pc += 4;
            }
            SparcInstruction::Unknown => return Err(SparcError::InvalidInstruction),
        }
        Ok(())
    }
}

#[derive(Debug)]
enum SparcInstruction {
    Nop,
    SETHI { dest_reg: u8, immediate: u32 },
    LDUW { dest_reg: u8, src_reg1: u8, immediate: i32 },
    AddRegister { dest_reg: u8, src_reg1: u8, src_reg2: u8 },
    Unknown,
}