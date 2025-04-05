use crate::hardware_abstraction::HardwareAbstraction; // HardwareAbstraction'ı içe aktarın

pub struct OpenriscArchitecture {
    hardware: HardwareAbstraction, // HardwareAbstraction örneğini tut
}

impl OpenriscArchitecture {
    pub fn new(hardware: HardwareAbstraction) -> Self {
        OpenriscArchitecture {
            hardware,
        }
    }

    pub fn execute_instruction(&self, instruction: &[u8]) {
        println!("OpenRISC komutu yürütülüyor: {:X?}", instruction);

        if instruction.is_empty() {
            println!("  Boş komut.");
            return;
        }

        match instruction[0] {
            0x01 => { // Örnek opcode: 0x01 (NOP)
                println!("  NOP komutu (opcode: 0x01) - İşlem yapılmıyor.");
            }
            0x02 => { // Örnek opcode: 0x02 (LOAD)
                println!("  LOAD komutu (opcode: 0x02) - Veri yükleme işlemi (örnek).");
                if instruction.len() > 6 {
                    // Örnek: 1. byte opcode, sonraki 4 byte adres, sonraki 1 byte boyut
                    let adres = u32::from_be_bytes([instruction[1], instruction[2], instruction[3], instruction[4]]) as u64;
                    let boyut = instruction[5] as usize;
                    println!("    Yüklenecek adres: 0x{:X}, Boyut: {}", adres, boyut);
                    let data = self.hardware.read_memory(adres, boyut);
                    println!("    Okunan veri: {:X?}", data);
                    // Gerçekte bu veri bir register'a yüklenirdi.
                } else {
                    println!("    Adres veya boyut bilgisi eksik.");
                }
            }
            0x03 => { // Örnek opcode: 0x03 (ADD)
                println!("  ADD komutu (opcode: 0x03) - Toplama işlemi (örnek).");
                println!("    Toplama işlemi (örnek olarak hiçbir şey yapılmıyor).");
            }
            0x04 => { // Örnek opcode: 0x04 (STORE)
                println!("  STORE komutu (opcode: 0x04) - Veri saklama işlemi (örnek).");
                if instruction.len() > 6 {
                    // Örnek: 1. byte opcode, sonraki 4 byte adres, sonraki 1 byte boyut, sonraki 'boyut' kadar veri
                    let adres = u32::from_be_bytes([instruction[1], instruction[2], instruction[3], instruction[4]]) as u64;
                    let boyut = instruction[5] as usize;
                    if instruction.len() >= 6 + boyut {
                        let data_to_write = &instruction[6..(6 + boyut)];
                        println!("    Saklanacak adres: 0x{:X}, Boyut: {}, Veri: {:X?}", adres, boyut, data_to_write);
                        self.hardware.write_memory(adres, data_to_write);
                    } else {
                        println!("    Yazılacak veri eksik.");
                    }
                } else {
                    println!("    Adres veya boyut bilgisi eksik.");
                }
            }
            _ => {
                println!("  Bilinmeyen komut (opcode: 0x{:X}).", instruction[0]);
            }
        }

        println!("OpenRISC komut yürütme tamamlandı.");
    }

    // Diğer OpenRISC mimarisine özgü fonksiyonlar buraya gelebilir.
}