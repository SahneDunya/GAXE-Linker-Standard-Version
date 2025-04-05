use crate::standard_library::StandardLibrary; // StandardLibrary'yi kullanabilmek için

pub struct PowerpcArchitecture {
    registers: [u32; 32],
    pc: u32,
    memory: *mut u8, // Sahne64 tarafından yönetilen bellek için bir pointer
    memory_size: usize,
    standard_library: StandardLibrary, // Çıktı almak için StandardLibrary
}

impl PowerpcArchitecture {
    pub fn new() -> Self {
        let memory_size = 4 * 1024 * 1024; // 4MB
        let memory = match super::memory::allocate(memory_size) {
            Ok(ptr) => ptr,
            Err(e) => {
                eprintln!("Hata: Bellek ayırma başarısız: {:?}", e);
                core::ptr::null_mut() // Hata durumunda null pointer
            }
        };
        PowerpcArchitecture {
            registers: [0; 32],
            pc: 0,
            memory,
            memory_size,
            standard_library: StandardLibrary::new(crate::gaxe_format::Architecture::PowerPC), // Doğru mimariyi belirtin
        }
    }

    // Belleği serbest bırakmak için bir drop metodu (isteğe bağlı)
    impl Drop for PowerpcArchitecture {
        fn drop(&mut self) {
            if !self.memory.is_null() {
                let result = unsafe { super::memory::free(self.memory, self.memory_size) };
                if let Err(e) = result {
                    eprintln!("Hata: Bellek serbest bırakma başarısız: {:?}", e);
                }
            }
        }
    }

    pub fn execute_instruction(&mut self, instruction_bytes: &[u8]) {
        if instruction_bytes.len() < 4 {
            println!("Hata: Geçersiz komut baytı uzunluğu");
            return;
        }
        let instruction = u32::from_be_bytes([
            instruction_bytes[0],
            instruction_bytes[1],
            instruction_bytes[2],
            instruction_bytes[3],
        ]);

        self.decode_and_execute(instruction);

        self.pc += 4;
    }

    fn decode_and_execute(&mut self, instruction: u32) {
        // **Basit Örnek Komut İşleme (NOP ve SYSCALL Örneği)**

        // NOP komutu
        if (instruction & 0xFC000000) == 0x60000000 {
            println!("NOP komutu yürütülüyor (0x{:X})", instruction);
        }
        // SYSCALL komutu (Örnek olarak 0x44000002'yi kullanıyoruz - gerçek syscall kodu farklı olabilir)
        else if instruction == 0x44000002 {
            println!("SYSCALL komutu algılandı");
            self.handle_syscall();
        }
        else {
            println!("Bilinmeyen komut yürütülüyor: 0x{:X}", instruction);
        }
    }

    fn handle_syscall(&mut self) {
        // **Örnek Sistem Çağrısı İşleme (Sadece çıktı için)**
        // Gerçek bir uygulamada, sistem çağrısı numarası ve argümanları registerlardan okunmalıdır.
        // Şu anda sadece basit bir çıktı örneği veriyoruz.

        // R1 register'ında çıktı stringinin adresi olduğunu varsayalım
        let string_address = self.get_register(1);
        // R2 register'ında çıktı stringinin uzunluğu olduğunu varsayalım
        let string_length = self.get_register(2) as usize;

        if self.memory.is_null() {
            eprintln!("Hata: Bellek ayrılmamış.");
            return;
        }

        // Güvenli olmayan blok içinde pointer aritmetiği ve bellek okuma
        unsafe {
            let start_ptr = self.memory.add(string_address as usize);
            let slice = core::slice::from_raw_parts(start_ptr, string_length);
            // Byte slice'ı &str'ye dönüştürme (güvenli olmayabilir, UTF-8 olduğunu varsayıyoruz)
            if let Ok(s) = core::str::from_utf8(slice) {
                self.standard_library.print_string(s);
            } else {
                eprintln!("Hata: Geçersiz UTF-8 stringi.");
            }
        }
    }

    pub fn set_register(&mut self, register_index: usize, value: u32) {
        if register_index < 32 {
            self.registers[register_index] = value;
        } else {
            println!("Hata: Geçersiz register indeksi: {}", register_index);
        }
    }

    pub fn get_register(&self, register_index: usize) -> u32 {
        if register_index < 32 {
            self.registers[register_index]
        } else {
            println!("Hata: Geçersiz register indeksi: {}", register_index);
            0
        }
    }

    pub fn write_memory_byte(&mut self, address: u32, value: u8) {
        if self.memory.is_null() {
            eprintln!("Hata: Bellek ayrılmamış.");
            return;
        }
        if (address as usize) < self.memory_size {
            unsafe {
                *self.memory.add(address as usize) = value;
            }
        } else {
            println!("Hata: Bellek sınırları dışında yazma girişimi: Adres = 0x{:X}", address);
        }
    }

    pub fn read_memory_byte(&self, address: u32) -> u8 {
        if self.memory.is_null() {
            eprintln!("Hata: Bellek ayrılmamış.");
            return 0;
        }
        if (address as usize) < self.memory_size {
            unsafe {
                *self.memory.add(address as usize)
            }
        } else {
            println!("Hata: Bellek sınırları dışında okuma girişimi: Adres = 0x{:X}", address);
            0
        }
    }

    // Diğer PowerPC mimarisine özgü fonksiyonlar buraya eklenebilir...
}