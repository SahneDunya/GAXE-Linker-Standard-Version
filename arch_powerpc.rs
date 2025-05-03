use crate::memory as sahne_memory; // Alias kullanmak karışıklığı önler
use crate::SahneError; // Sahne64 hata türü
use crate::standard_library::StandardLibrary; // StandardLibrary'yi kullanabilmek için

use core::ptr; // İşaretçi operasyonları için
use alloc::vec::Vec; // Gerekirse dinamik vektör için
use alloc::string::String; // Gerekirse string için

pub struct PowerpcArchitecture {
    registers: [u32; 32],
    pc: u32,
    // Sahne64 tarafından yönetilen bellek için bir pointer ve boyutu
    vm_memory_ptr: *mut u8,
    vm_memory_size: usize,
    // Standard kütüphane instance'ı
    standard_library: StandardLibrary,
}

// Belleği serbest bırakmak için Drop trait'ini implemente et
// NOT: Bu blok, impl PowerpcArchitecture bloğunun dışında olmalıdır.
impl Drop for PowerpcArchitecture {
    fn drop(&mut self) {
        // Eğer belleğe bir işaretçi varsa ve null değilse serbest bırak
        if !self.vm_memory_ptr.is_null() {
            println!("PowerPC VM belleği serbest bırakılıyor (Adres: {:p}, Boyut: {})...", self.vm_memory_ptr, self.vm_memory_size);
             // super::memory::release yerine sahne_memory::release kullanın
             // release fonksiyonu pointer argümanı aldığı için unsafe blok içinde çağrılabilir
             match sahne_memory::release(self.vm_memory_ptr, self.vm_memory_size) {
                 Ok(_) => println!("PowerPC VM belleği başarıyla serbest bırakıldı."),
                 Err(e) => eprintln!("PowerPC VM belleğini serbest bırakma hatası: {:?}", e),
             }
        }
        // İşaretçiyi null yapmaya gerek yok, Drop sadece bir kere çağrılır normalde
    }
}


impl PowerpcArchitecture {
    /// Yeni bir `PowerpcArchitecture` örneği oluşturur ve bellek ayırır.
    /// Bellek tahsisi Sahne64 memory modülü kullanılır.
    /// Bellek tahsisi başarısız olursa `SahneError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, SahneError> {
        println!("Sahne64 kullanarak {} byte PowerPC VM belleği tahsis ediliyor...", vm_memory_size);
        // Sahne64 memory modülünü kullanarak VM için bellek alanı tahsis et
        // super::memory::allocate yerine sahne_memory::allocate kullanın
        let vm_memory_ptr = sahne_memory::allocate(vm_memory_size)?; // Result handling

        println!("PowerPC VM belleği tahsis edildi: {:p}", vm_memory_ptr);

        Ok(PowerpcArchitecture {
            registers: [0; 32], // PowerPC genel amaçlı registerları (GPRs)
            pc: 0, // Başlangıç Program Sayacı (genellikle 0 veya entry point)
            vm_memory_ptr,
            vm_memory_size,
            standard_library, // StandardLibrary örneğini al
        })
    }

    // Bellek erişimi için yardımcı fonksiyon (isteğe bağlı ama güvenli)
     fn get_memory_slice(&mut self) -> &mut [u8] {
         if self.vm_memory_ptr.is_null() {
              panic!("Attempted to get memory slice from null pointer");
         }
         unsafe { core::slice::from_raw_parts_mut(self.vm_memory_ptr, self.vm_memory_size) }
     }


    pub fn execute_instruction(&mut self, instruction_bytes: &[u8]) {
        // ... komut fetch etme ve PC ilerletme mantığı ...
        if instruction_bytes.len() < 4 {
            println!("Hata: Geçersiz komut baytı uzunluğu");
             // VM yürütme hatası işleme
            return;
        }
        // PowerPC genellikle big-endian'dır
        let instruction = u32::from_be_bytes([
            instruction_bytes[0],
            instruction_bytes[1],
            instruction_bytes[2],
            instruction_bytes[3],
        ]);

        let current_pc = self.pc;
        println!("PowerPC komutu yürütülüyor (PC: 0x{:X}): 0x{:X}", current_pc, instruction);


        self.decode_and_execute(instruction);

        // PC'yi ilerlet (dallanma/zıplama komutları bunu değiştirebilir)
        self.pc += 4;
    }

    fn decode_and_execute(&mut self, instruction: u32) {
        // **Basit Örnek Komut İşleme (NOP ve SYSCALL Örneği)**

        // PowerPC opcode'ları genellikle ilk 6 bittir.
        let opcode = (instruction >> 26) & 0x3F;

        match opcode {
             0x10 => { // Örnek PowerPC opcode (örneğin X formattaki bazı komutlar)
                  let xo = (instruction >> 1) & 0x3FF; // Genişletilmiş opcode
                  match xo {
                       0x150 => { // sync
                           println!("SYNC komutu yürütülüyor (0x{:X})", instruction);
                       },
                       _ => {
                           println!("Bilinmeyen X formattaki komut yürütülüyor: 0x{:X}", instruction);
                           // VM yürütme hatası işleme
                       }
                  }
             }
             0x11 => { // Örnek PowerPC opcode (örneğin SC - Syscall)
                  // SC (System Call) komutu PowerPC'de genellikle opcode 17 (0x11)
                  println!("SYSCALL komutu algılandı (0x{:X})", instruction);
                  // SYSCALL numarasını ve argümanları registerlardan oku
                  // Örnek: R3 genellikle syscall numarasını, R4-R10 argümanları tutar.
                   let syscall_number = self.get_register(3);
                   let arg1 = self.get_register(4); // R4
                  // ...

                  // VM içinden gelen bu syscall'u işleyen bir fonksiyon çağır.
                  // Bu fonksiyon Sahne64 API'sını kullanacaktır.
                  // self.handle_vm_syscall(syscall_number as u64, ...);
                  // Hata veya dönüş değeri registerlara yazılmalıdır.

                   // Örnek: Standard Library'nin syscall handler'ını çağır
                   // Varsayım: StandardLibrary içinde syscall'ları işleyen bir metod var.
                    let result = self.standard_library.handle_syscall(syscall_number as u64, ...);
                   // // Sonuca göre registerları güncelle
                    match result {
                         Ok(ret_val) => { self.set_register(3, ret_val as u32); /* R3'e dönüş değerini yaz */ self.set_register(4, 0); /* R4'e başarı (0) yaz */ },
                         Err(e) => { self.set_register(4, e.to_sahne_error_code() as u32); /* R4'e hata kodunu yaz */ } // SahneError'ı bir koda çevirme
                    }

                   // Şimdilik sadece çıktı verelim
                   self.handle_syscall_example(); // Örnek placeholder handler

             }
            // ... diğer opcode durumları ...
            _ => {
                println!("Bilinmeyen PowerPC opcode 0x{:X} yürütülüyor (0x{:X})", opcode, instruction);
                 // VM yürütme hatası işleme
            }
        }
    }

    // Bu fonksiyon artık doğrudan syscall komutunu işlemez, sadece örnek çıktı verir.
    // Gerçek syscall işleme handle_vm_syscall gibi bir fonksiyonda olur.
    fn handle_syscall_example(&mut self) {
        println!("  -> Örnek SYSCALL işleniyor (Sadece çıktı simülasyonu)");
        // Gerçek bir uygulamada, sistem çağrısı numarası ve argümanları registerlardan okunmalıdır.
        // Şu anda sadece basit bir çıktı örneği veriyoruz.

        // R1 register'ında çıktı stringinin adresi olduğunu varsayalım (VM adresi)
        let string_address = self.get_register(1);
        // R2 register'ında çıktı stringinin uzunluğu olduğunu varsayalım
        let string_length = self.get_register(2) as usize;

        // Bellek pointerı geçerli mi kontrol et
        if self.vm_memory_ptr.is_null() {
            eprintln!("Hata: VM belleği ayrılmamış.");
            // VM'e hata durumu bildir (belki registerları güncelleyerek)
            return;
        }

        // Güvenli olmayan blok içinde pointer aritmetiği ve bellek okuma
        // Sınır kontrolünü unutma!
        if (string_address as usize) + string_length > self.vm_memory_size {
             eprintln!("Hata: SYSCALL çıktı stringi bellek sınırları dışında (Adres: 0x{:X}, Uzunluk: {})", string_address, string_length);
              // VM'e hata durumu bildir
             return;
        }

        unsafe {
            let start_ptr = self.vm_memory_ptr.add(string_address as usize);
            let slice = core::slice::from_raw_parts(start_ptr, string_length);
            // Byte slice'ı &str'ye dönüştürme (güvenli olmayabilir, UTF-8 olduğunu varsayıyoruz)
            if let Ok(s) = core::str::from_utf8(slice) {
                // StandardLibrary Sahne64 resource::write kullanır
                self.standard_library.print_string(s);
            } else {
                eprintln!("Hata: VM belleğinde geçersiz UTF-8 stringi (Adres: 0x{:X}).", string_address);
                 // VM'e hata durumu bildir
            }
        }
        // SYSCALL dönüş değerini ve başarı/hata bayrağını registerlara yaz (simülasyon)
         self.set_register(3, string_length as u32); // Okunan/yazılan byte sayısı
         self.set_register(4, 0); // Başarı
    }

    // VM içinden gelen gerçek syscall'ları işleyen fonksiyon (Sahne64 API'sını kullanır)
     fn handle_vm_syscall(&mut self, syscall_num: u64, args: &[u64]) -> Result<u64, SahneError> {
    //     // Syscall numarasına göre Sahne64 API fonksiyonlarını çağır
         match syscall_num {
    //         // Örnek: Dosya açma
             VM_SYSCALL_OPEN => {
                  let filename_vm_addr = args[0] as usize;
                  let flags = args[1] as u32;
    //              // VM belleğindeki dosya adı stringini oku
                  let vm_memory = self.get_memory_slice(); // Veya vm_memory_ptr ve size kullan
                  let filename_slice = // vm_memory'den null-terminated veya uzunluklu string oku
                  let filename_str = core::str::from_utf8(filename_slice).map_err(|_| SahneError::InvalidParameter)?; // veya NamingError
    //
    //              // Sahne64 resource::acquire çağrısı yap
                  let handle = resource::acquire(filename_str, flags)?;
    //
    //              // VM'e Handle'ı dosya tanımlayıcısı olarak dön (VM runner'ın Handle-FD map'ini yönetmesi lazım)
    //              // Örneğin, VM FD = 3, Sahne64 Handle = Handle(123) gibi
                   self.map_sahne_handle_to_vm_fd(handle);
                   Ok(vm_fd as u64)
                   Ok(handle.raw()) // Basitlik için raw handle'ı dönelim
             }
    //         // ... diğer syscall'lar ...
             _ => {
                 eprintln!("Bilinmeyen PowerPC VM syscall: {}", syscall_num);
                 Err(SahneError::NotSupported) // Veya daha spesifik VM hatası
             }
         }
    //     // Bu fonksiyonun dönüş değeri VM registerlarına yazılır.
     }


    pub fn set_register(&mut self, register_index: usize, value: u32) {
        if register_index < 32 {
            self.registers[register_index] = value;
        } else {
            eprintln!("Hata: Geçersiz PowerPC register indeksi: {}", register_index);
        }
    }

    pub fn get_register(&self, register_index: usize) -> u32 {
        if register_index < 32 {
            self.registers[register_index]
        } else {
            eprintln!("Hata: Geçersiz PowerPC register indeksi: {}", register_index);
            // Geçersiz erişimde ne döneceği VM modeline bağlı
            0 // Varsayılan veya hata değeri
        }
    }

    // VM belleğine byte yazma fonksiyonu
    pub fn write_memory_byte(&mut self, address: u32, value: u8) {
        // VM adresi, VM belleği bloğu içinde offset olarak kabul edilir.
        let offset = address as usize;

        if self.vm_memory_ptr.is_null() {
            eprintln!("Hata: VM belleği ayrılmamış.");
             // VM'e hata bildir
            return;
        }

        // Sınır kontrolü
        if offset < self.vm_memory_size {
            unsafe {
                // Pointer aritmetiği ile doğru adrese git ve yaz
                *self.vm_memory_ptr.add(offset) = value;
            }
        } else {
            eprintln!("Hata: Bellek sınırları dışında yazma girişimi: VM Adres = 0x{:X}, Boyut = {}", address, self.vm_memory_size);
            // VM'e hata bildir
        }
    }

    // VM belleğinden byte okuma fonksiyonu
    pub fn read_memory_byte(&self, address: u32) -> u8 {
        // VM adresi, VM belleği bloğu içinde offset olarak kabul edilir.
        let offset = address as usize;

        if self.vm_memory_ptr.is_null() {
            eprintln!("Hata: VM belleği ayrılmamış.");
             // VM'e hata bildir, varsayılan değer dön
            return 0; // Hata durumunda 0 dönmek yaygın
        }

        // Sınır kontrolü
        if offset < self.vm_memory_size {
            unsafe {
                // Pointer aritmetiği ile doğru adrese git ve oku
                *self.vm_memory_ptr.add(offset)
            }
        } else {
            eprintln!("Hata: Bellek sınırları dışında okuma girişimi: VM Adres = 0x{:X}, Boyut = {}", address, self.vm_memory_size);
             // VM'e hata bildir, varsayılan değer dön
            0 // Hata durumunda 0 dönmek yaygın
        }
    }

    // Word (32-bit) okuma/yazma gibi fonksiyonlar da eklenebilir.
    // PowerPC big-endian olduğu için endianness'e dikkat edilmelidir.
     pub fn read_memory_word(&self, address: u32) -> u32 { ... }
     pub fn write_memory_word(&mut self, address: u32, value: u32) { ... }


    // Diğer PowerPC mimarisine özgü fonksiyonlar buraya eklenebilir...
    // İstisna işleme, kesme işleme vb.
}
