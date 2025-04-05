use crate::gaxe_format::Architecture;
use super::{memory, fs, arch}; // Sahne64 modüllerini içeri aktar
use super::standard_library::StandardLibrary; // Standart kütüphaneyi içeri aktar

pub struct X86Architecture {
    // x86 mimarisinin iç durumunu tutacak alanlar buraya eklenebilir
    registers: X86Registers,
    memory: Vec<u8>, // Sanal x86 belleği
    // memory_manager: MemoryManager, // Eğer daha karmaşık bir bellek yönetimi gerekirse
    standard_library: StandardLibrary, // Standart kütüphaneye erişim
}

// X86 registerlarını temsil eden struct
#[derive(Debug)]
struct X86Registers {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    eip: u32,
    // ... diğer registerlar ...
}

impl X86Architecture {
    pub fn new(memory_size: usize, architecture: Architecture, standard_library: StandardLibrary) -> Self {
        X86Architecture {
            registers: X86Registers::new(),
            memory: vec![0; memory_size], // Belirli bir boyutta sanal bellek oluştur
            standard_library,
        }
    }

    pub fn execute_instruction(&mut self, instruction_pointer: &mut u32, code: &[u8]) {
        if *instruction_pointer as usize >= code.len() {
            println!("Komut sınırının dışına çıkıldı!");
            return;
        }

        let opcode = code[*instruction_pointer as usize];
        println!("Yürütülen opcode: 0x{:x} (EIP: 0x{:x})", opcode, *instruction_pointer);

        match opcode {
            0xB8 => { // MOV EAX, imm32
                if (*instruction_pointer as usize) + 5 <= code.len() {
                    let immediate = u32::from_le_bytes([
                        code[(*instruction_pointer as usize) + 1],
                        code[(*instruction_pointer as usize) + 2],
                        code[(*instruction_pointer as usize) + 3],
                        code[(*instruction_pointer as usize) + 4],
                    ]);
                    self.registers.eax = immediate;
                    *instruction_pointer += 5;
                    println!("MOV EAX, {:x} komutu yürütüldü. EAX = {:x}", immediate, self.registers.eax);
                } else {
                    println!("Geçersiz MOV EAX, imm32 komutu formatı!");
                    *instruction_pointer += 1; // Hata durumunda bile ilerle
                }
            }
            // **BELLEK OKUMA ÖRNEĞİ**
            0x8B => { // MOV register, [memory] (çok basitleştirilmiş örnek)
                if (*instruction_pointer as usize) + 2 <= code.len() {
                    let dest_register = (code[(*instruction_pointer as usize) + 1] >> 3) & 0x7; // Basit register kodu alımı
                    let mem_offset = code[(*instruction_pointer as usize) + 2] as u32; // Basit offset

                    if mem_offset as usize < self.memory.len() {
                        let value = self.memory[mem_offset as usize] as u32; // Tek bayt okuma (örnek)
                        match dest_register {
                            0 => self.registers.eax = value,
                            1 => self.registers.ecx = value,
                            // ... diğer registerlar ...
                            _ => println!("Desteklenmeyen hedef register: {}", dest_register),
                        }
                        println!("MOV register, [0x{:x}] komutu yürütüldü. Register({}) = 0x{:x}", mem_offset, dest_register, value);
                        *instruction_pointer += 3;
                    } else {
                        println!("Geçersiz bellek adresi: 0x{:x}", mem_offset);
                        *instruction_pointer += 3;
                    }
                } else {
                    println!("Geçersiz MOV register, [memory] komutu formatı!");
                    *instruction_pointer += 1;
                }
            }
            // **SİSTEM ÇAĞRISI ÖRNEĞİ (ÇOK BASİT)**
            0xCD => { // INT 0x80 (Örnek sistem çağrısı)
                if (*instruction_pointer as usize) + 1 < code.len() && code[(*instruction_pointer as usize) + 1] == 0x80 {
                    let syscall_number = self.registers.eax; // Genellikle EAX'ta sistem çağrısı numarası bulunur
                    println!("Sistem çağrısı algılandı: {}", syscall_number);
                    match syscall_number {
                        1 => { // Örnek: print_string sistem çağrısı
                            let address = self.registers.ebx as usize; // Argüman olarak EBX'te adres bekliyoruz (çok basit)
                            // Güvenlik için bellek sınırlarını kontrol etmeliyiz!
                            if address < self.memory.len() {
                                // Null-terminated string oku (basit örnek)
                                let mut s = String::new();
                                let mut current_address = address;
                                while current_address < self.memory.len() {
                                    let byte = self.memory[current_address];
                                    if byte == 0 {
                                        break;
                                    }
                                    s.push(byte as char);
                                    current_address += 1;
                                }
                                self.standard_library.print_string(&s);
                            } else {
                                println!("Geçersiz bellek adresi (print_string): 0x{:x}", address);
                            }
                        }
                        // ... diğer sistem çağrıları için durumlar ...
                        _ => println!("Bilinmeyen sistem çağrısı: {}", syscall_number),
                    }
                    *instruction_pointer += 2;
                } else {
                    println!("Geçersiz INT 0x80 formatı!");
                    *instruction_pointer += 1;
                }
            }
            // ... diğer opcode'lar ...
            _ => {
                println!("Bilinmeyen opcode yürütülüyor: 0x{:x}", opcode);
                *instruction_pointer += 1; // Bilinmeyen komutta ilerle
            }
        }
    }

    // Diğer x86 mimarisine özgü fonksiyonlar...

    pub fn get_eax_register(&self) -> u32 {
        self.registers.eax
    }

    pub fn get_eip_register(&self) -> u32 {
        self.registers.eip
    }

    // Belleğe veri yazmak için örnek bir fonksiyon
    pub fn write_memory(&mut self, address: u32, data: &[u8]) {
        if (address as usize) < self.memory.len() && (address as usize) + data.len() <= self.memory.len() {
            self.memory[(address as usize)..(address as usize) + data.len()].copy_from_slice(data);
        } else {
            println!("Geçersiz bellek yazma adresi: 0x{:x}", address);
        }
    }
}

impl X86Registers {
    pub fn new() -> Self {
        X86Registers {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            eip: 0,
            // ... diğer registerlar için başlangıç değerleri ...
        }
    }
}