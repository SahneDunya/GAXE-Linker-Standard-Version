use crate::memory as sahne_memory;
use crate::SahneError; // Sahne64 hata türü

use crate::standard_library::StandardLibrary; // StandardLibrary'yi kullanabilmek için

use core::ptr; // İşaretçi operasyonları için
use core::fmt; // Debug ve Display için
use alloc::string::String; // String kullanıldığı için
use alloc::vec::Vec; // Vec kullanıldığı için
use alloc::format; // format! makrosu kullanıldığı için


pub struct LoongarchArchitecture {
    // LoongArch mimarisinin iç durumunu tutacak alanlar
    registers: [u64; 32], // LoongArch genel amaçlı registerları (GPRs)
    pc: u64, // Program Counter
    // Sahne64 tarafından yönetilen VM belleği için pointer ve boyutu
    vm_memory_ptr: *mut u8,
    vm_memory_size: usize,
    // Standard kütüphane instance'ı (VM içindeki guest code tarafından syscall'lar aracılığıyla kullanılır)
    standard_library: StandardLibrary,
    // ... diğer mimariye özgü durumlar (CSRs, TLB/MMU state vb.) ...
}

// LoongArch VM yürütme hataları
#[derive(Debug)] // fmt::Display de burada derive edilebilir
pub enum LoongArchError {
    InvalidInstructionFormat, // Geçersiz komut formatı
    UnsupportedOpcode(u32), // Desteklenmeyen ana opcode (6 bit)
    UnsupportedSubOpcode(u32, u32), // Desteklenmeyen alt opcode
    ExecutionError(String),   // Genel yürütme hataları için
    MemoryAccessError(u64), // Geçersiz bellek erişim adresi
    SystemCallError(SahneError), // Sahne64'ten dönen syscall hatası
    // ... diğer hatalar eklenebilir ...
}

// SahneError'dan LoongArchError::SystemCallError'a dönüşüm
impl From<SahneError> for LoongArchError {
    fn from(err: SahneError) -> Self {
        LoongArchError::SystemCallError(err)
    }
}

// fmt::Display implementasyonu (mevcut koddan)
impl fmt::Display for LoongArchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoongArchError::InvalidInstructionFormat => write!(f, "Geçersiz Komut Formatı"),
            LoongArchError::UnsupportedOpcode(opcode) => write!(f, "Desteklenmeyen Ana Opcode: 0x{:x}", opcode),
            LoongArchError::UnsupportedSubOpcode(opcode, sub_opcode) => write!(f, "Desteklenmeyen Alt Opcode (Opcode: 0x{:x}, Alt Opcode: 0x{:x})", opcode, sub_opcode),
            LoongArchError::ExecutionError(msg) => write!(f, "Yürütme Hatası: {}", msg),
            LoongArchError::MemoryAccessError(address) => write!(f, "Geçersiz Bellek Erişim Adresi: 0x{:x}", address),
            LoongArchError::SystemCallError(e) => write!(f, "Sistem Çağrısı Hatası: {:?}", e), // SahneError'ın Debug çıktısını kullan
        }
    }
}

// std::error::Error trait implementasyonu no_std ortamında std feature gerektirir.
// Eğer std feature yoksa bu kısım koşullu derlenmelidir.
 #[cfg(feature = "std")]
 impl std::error::Error for LoongArchError {}


// Belleği serbest bırakmak için Drop trait'ini implemente et
impl Drop for LoongarchArchitecture {
    fn drop(&mut self) {
         // Eğer belleğe bir işaretçi varsa ve null değilse serbest bırak
         if !self.vm_memory_ptr.is_null() {
             println!("LoongArch VM belleği serbest bırakılıyor (Adres: {:p}, Boyut: {})...", self.vm_memory_ptr, self.vm_memory_size);
              // Sahne64 memory::release fonksiyonunu kullanın
              match sahne_memory::release(self.vm_memory_ptr, self.vm_memory_size) {
                  Ok(_) => println!("LoongArch VM belleği başarıyla serbest bırakıldı."),
                  Err(e) => eprintln!("LoongArch VM belleğini serbest bırakma hatası: {:?}", e),
              }
         }
    }
}


impl LoongarchArchitecture {
    /// Yeni bir `LoongarchArchitecture` örneği oluşturur ve VM belleğini Sahne64 kullanarak tahsis eder.
    /// Bellek tahsisi başarısız olursa `SahneError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, SahneError> {
         println!("Sahne64 kullanarak {} byte LoongArch VM belleği tahsis ediliyor...", vm_memory_size);
        // Sahne64 memory modülünü kullanarak VM için bellek alanı tahsis et
        let vm_memory_ptr = sahne_memory::allocate(vm_memory_size)?; // sahne_memory::allocate çağrısı, hata Result ile propagate edilir.

         println!("LoongArch VM belleği tahsis edildi: {:p}", vm_memory_ptr);

        Ok(LoongarchArchitecture {
            registers: [0; 32], // LoongArch GPRs (R0-R31), 64-bit mimaride u64
            pc: 0, // Başlangıç Program Sayacı (genellikle 0 veya entry point adresi)
            vm_memory_ptr,
            vm_memory_size,
            standard_library, // StandardLibrary örneğini al
            // ... diğer durumları başlat ...
        })
    }

     // Tahsis edilen bellek alanına güvenli erişim için yardımcı fonksiyon
     // VM belleği slice'ını döndürür. İşaretçi null ise panikleyebilir.
     fn get_memory_slice(&mut self) -> &mut [u8] {
         if self.vm_memory_ptr.is_null() {
              // Bellek tahsis hatası sonrası veya Drop sonrası çağrılırsa panikleyebilir.
              panic!("Attempted to get memory slice from null VM pointer");
         }
         unsafe { core::slice::from_raw_parts_mut(self.vm_memory_ptr, self.vm_memory_size) }
     }

    // LoongArch komutunu yürütür.
    // signature güncellendi: self artık mutable referans, standard_library field oldu.
    // instruction_bytes yerine VM belleğindeki PC'den instruction fetch edilecek.
    pub fn execute_next_instruction(&mut self) -> Result<(), LoongArchError> {
         let pc = self.pc;
        if pc as usize >= self.vm_memory_size {
             // Kod (VM belleğinde olmalı) sınırlarının dışına çıkıldı
             eprintln!("Hata: VM belleği sınırının dışına çıkıldı (PC: 0x{:x}, Bellek Boyutu: {})", pc, self.vm_memory_size);
             return Err(LoongArchError::ExecutionError(format!("PC out of bounds: 0x{:x}", pc)));
         }

        // VM belleğinden komut baytlarını oku (LoongArch genellikle 32-bit veya 64-bit komutlar kullanır)
        // Basitlik için 4 byte (32-bit) komut varsayalım.
        let instruction_bytes_res = self.read_memory_slice(pc, 4); // VM belleğinden 4 byte oku

        let instruction_bytes = match instruction_bytes_res {
            Ok(slice) => {
                if slice.len() < 4 {
                     // Bu durum get_memory_slice ve read_memory_slice'ın sınır kontrolü ile yakalanmalıydı,
                     // ama ek bir kontrol zarar vermez. Tam 4 byte okunamadı.
                     eprintln!("Hata: Komut fetch sırasında yetersiz byte (PC: 0x{:x})", pc);
                     return Err(LoongArchError::InvalidInstructionFormat);
                }
                slice
            },
            Err(e) => {
                 // Bellek okuma hatası (read_memory_slice'dan gelen &'static str)
                 eprintln!("Hata: Komut fetch sırasında bellek okuma hatası: {}", e);
                 return Err(LoongArchError::MemoryAccessError(pc)); // Bellek erişim hatası
            }
        };

        // LoongArch komut formatı genellikle ilk 6 bit opcode kullanır (DI, CI, II, RI, RCE, Z vb. formatlar)
        // Komut baytlarını u32'ye çevir (LoongArch little-endian veya big-endian olabilir, sisteme göre ayarla)
         let instruction = u32::from_le_bytes([ // LoongArch 64-bit little-endian yaygın
             instruction_bytes[0],
             instruction_bytes[1],
             instruction_bytes[2],
             instruction_bytes[3],
         ]);

        // Ana opcode'u çıkar
        let main_opcode = (instruction >> 26) & 0x3F; // İlk 6 bit


        // 3. Opcode'a göre işlem yap (Örnek opcode işleme)
        match main_opcode {
            0x00 => { // Özel opcode ailesi (örn: NOP, mfcp, mtcp vb. funct alanına göre değişir)
                 let funct = (instruction >> 5) & 0x7; // Genellikle bit [7:5] funct alanıdır.
                 match funct {
                      0x00 => { // Örnek: NOP (instruction = 0x00000000)
                           if instruction == 0x00000000 {
                               println!("[LoongArch] NOP komutu yürütülüyor (PC: 0x{:x}).", pc);
                               self.pc += 4; // PC'yi ilerlet (LoongArch komutları genellikle 4 byte)
                               Ok(())
                           } else {
                                // 0x00 opcode ailesinde farklı funct değerleri için diğer komutlar
                                eprintln!("[LoongArch] Bilinmeyen 0x00 opcode alt türü (funct: 0x{:x}, instruction: 0x{:x})", funct, instruction);
                                self.pc += 4; // Yine de PC'yi ilerlet? Veya hata?
                                 Err(LoongArchError::UnsupportedSubOpcode(main_opcode, funct))
                           }
                      }
                      // ... diğer funct değerleri için eşleşmeler ...
                      _ => {
                           eprintln!("[LoongArch] Bilinmeyen 0x00 opcode alt türü (funct: 0x{:x}, instruction: 0x{:x})", funct, instruction);
                            self.pc += 4; // PC'yi ilerlet
                            Err(LoongArchError::UnsupportedSubOpcode(main_opcode, funct))
                      }
                 }
            }
             // Örnek: Basit çıktı alma syscall/komutu (gerçek LoongArch'ta syscall opcode 0x14 olabilir)
             // Burada sadece opcode 0x02'yi bir örnek çıktı komutu olarak ele alalım (gerçekçi değil)
            0x02 => {
                println!("[LoongArch] Çıktı komutu algılandı (PC: 0x{:x}).", pc);
                // Çıktı verisini VM belleğinden oku (argümanlar registerlarda veya komutta olabilir)
                // Basitlik için sabit bir stringi standard_library üzerinden yazdıralım
                self.standard_library.print_string("[LoongArch] VM Çıktısı Örneği.\n");
                self.pc += 4; // PC'yi ilerlet
                Ok(())
            }
             0x14 => { // Örnek: SYSCALL (opcode 0x14)
                  println!("[LoongArch] SYSCALL komutu algılandı (PC: 0x{:x}).", pc);
                  // Syscall numarası ve argümanlar registerlarda bulunur (LoongArch ABI'sına göre)
                  // Örnek: a0 (R4) -> syscall numarası, a1-a7 (R5-R11) -> argümanlar
                  let syscall_num = self.registers[4]; // R4'teki değer (a0)
                  // Argümanları topla
                   let args = &[self.registers[5], self.registers[6], ...];

                  // VM içinden gelen bu syscall'u işleyen bir fonksiyon çağır.
                  // Bu fonksiyon Sahne64 API'sını kullanacaktır.
                  // Hata dönebilir, bunu yakalayıp LoongArchError::SystemCallError'a çeviriyoruz.
                  match self.handle_vm_syscall(syscall_num, /* args */ &[]) {
                       Ok(return_value) => {
                            println!("  -> Syscall {} başarıyla işlendi, dönüş değeri: 0x{:x}", syscall_num, return_value);
                            // Syscall dönüş değerini registera yaz (LoongArch'ta genellikle R4 - a0)
                            self.registers[4] = return_value;
                            // Hata bayrağını (varsa) temizle (örn: R5 - a1 = 0)
                             self.registers[5] = 0;
                       },
                       Err(e) => {
                            eprintln!("  -> Syscall {} işleme hatası: {:?}", syscall_num, e);
                            // Hata kodunu registera yaz (örn: R4 - a0)
                            self.registers[4] = 0xFFFFFFFFFFFFFFFF; // Genellikle negatif hata kodları
                            // Hata bayrağını set et (örn: R5 - a1 = -1 veya bir hata numarası)
                             self.registers[5] = (-1i64) as u64;
                            // SahneError'ı VM'in hata koduna çevirmek gerekebilir.
                             let vm_error_code = map_sahne_error_to_vm_error_code(e);
                             self.registers[4] = vm_error_code;
                       }
                  }

                  self.pc += 4; // PC'yi ilerlet
                  Ok(())
             }
            // ... diğer opcode'lar için case'ler ...
            _ => {
                eprintln!("[LoongArch] Bilinmeyen ana opcode: 0x{:x} (PC: 0x{:x})", main_opcode, pc);
                 self.pc += 4; // Bilinmeyen komutta bile PC'yi ilerletmek yaygın (ama istisna da olabilir)
                Err(LoongArchError::UnsupportedOpcode(main_opcode as u32)) // Bilinmeyen opcode hatası
            }
        }
    }

    // VM içinden gelen gerçek syscall'ları işleyen fonksiyon (Sahne64 API'sını kullanır)
    // Dönüş değeri (u64) genellikle a0 registerına yazılır.
    // Hata durumunda Err(LoongArchError) döner (syscall sırasında Sahne64 hatası olabilir).
    fn handle_vm_syscall(&mut self, syscall_num: u64, _args: &[u64]) -> Result<u64, LoongArchError> {
        println!("  -> LoongArch VM Syscall işleniyor: {}", syscall_num);
        // Syscall numarasına göre Sahne64 API fonksiyonlarını çağır
        // _args slice'ı VM registerlarındaki argümanları temsil eder.
        match syscall_num {
            // Örnek: Sahne64 task::exit syscall'u (VM_SYSCALL_EXIT = 4 olsun)
            4 => { Syscall 4: Exit
                 // Çıkış kodu R5'te (a1) olsun
                  let exit_code = args[0] as i32; // args[0] == R5
                 // task::exit fonksiyonu geri dönmez, bu fonksiyon da geri dönmemeli veya özel bir durum bildirmeli
                 // Şimdilik sadece çıktı verelim ve Ok(0) dönelim (gerçekçi değil)
                 println!("    -> VM Syscall: task::exit çağrısı simüle ediliyor.");
                  task::exit(exit_code); // Gerçekte bu satır çağrılır ve geri dönmez
                 Ok(0) // Başarı değeri
            }
             // Örnek: Sahne64 resource::write syscall'u (VM_SYSCALL_WRITE = 7 olsun)
             7 => { // Syscall 7: Write
                  // Argümanlar: a0 (R4) -> Handle, a1 (R5) -> buffer adresi, a2 (R6) -> buffer boyutu
                   let handle_raw = args[0];
                   let vm_buffer_addr = args[1] as usize;
                   let size = args[2] as usize;
                  // Argümanları registerlardan alalım
                   let handle_raw = self.registers[4]; // a0
                   let vm_buffer_addr = self.registers[5] as usize; // a1
                   let size = self.registers[6] as usize; // a2

                   println!("    -> VM Syscall: resource::write çağrısı simüle ediliyor. Handle: {}, VM Adres: 0x{:x}, Boyut: {}", handle_raw, vm_buffer_addr, size);


                   // VM belleğindeki buffer'a erişmek için slice al
                   // Sınır kontrolünü yap!
                   if vm_buffer_addr + size > self.vm_memory_size {
                        eprintln!("    -> Hata: resource::write Syscall: Bellek sınırları dışında buffer (VM Adres: 0x{:x}, Boyut: {}, Bellek Boyutu: {})", vm_buffer_addr, size, self.vm_memory_size);
                         // SahneError::InvalidAddress gibi bir hataya çevirelim
                         return Err(LoongArchError::SystemCallError(SahneError::InvalidAddress));
                   }
                   let vm_memory_slice = self.get_memory_slice(); // Mutable slice alır
                   let buffer_slice = &vm_memory_slice[vm_buffer_addr .. vm_buffer_addr + size];

                   // Handle'ı Sahne64 Handle struct'ına çevir
                   let sahne64_handle = crate::Handle(handle_raw);

                   // Sahne64 resource::write çağrısı yap
                   match crate::resource::write(sahne64_handle, buffer_slice) {
                       Ok(bytes_written) => {
                            // Başarı durumunda yazılan byte sayısını dön
                            Ok(bytes_written as u64)
                       }
                       Err(e) => {
                            // SahneError'ı propagate et (From implementasyonu kullanır)
                            Err(e.into()) LoongArchError::SystemCallError(e)
                       }
                   }
             }
            // ... diğer VM syscall'ları için eşleşmeler ...
            // Örnek: read, open, close, allocate, spawn_task, sleep vb.
            _ => {
                eprintln!("  -> Bilinmeyen LoongArch VM syscall: {}", syscall_num);
                // SahneError::NotSupported gibi bir hataya çevirelim
                Err(LoongArchError::SystemCallError(SahneError::NotSupported))
            }
        }
        // Bu fonksiyonun dönüş değeri (Ok(value)) VM registerlarına yazılır.
        // Hata durumunda (Err(e)) ise VM registerlarına hata kodu yazılır ve/veya bayrak set edilir.
    }


    // VM belleğinden belirli bir adresten slice okuma (read-only)
    // instruction fetch veya veri yükleme için kullanılır.
    fn read_memory_slice(&self, address: u64, len: usize) -> Result<&[u8], &'static str> {
        let offset = address as usize;

         // Bellek pointerı geçerli mi kontrol et
         if self.vm_memory_ptr.is_null() {
              eprintln!("Hata: VM belleği ayrılmamış, okuma yapılamaz.");
              return Err("VM belleği ayrılmamış");
         }

        // Sınır kontrolü
        if offset < self.vm_memory_size && offset + len <= self.vm_memory_size {
             // Read-only slice al (get_memory_slice mut döndürdüğü için burada raw pointer kullanmak daha doğru)
             let vm_memory = unsafe { core::slice::from_raw_parts(self.vm_memory_ptr, self.vm_memory_size) };
             Ok(&vm_memory[offset .. offset + len])
        } else {
             eprintln!("Hata: Bellek sınırları dışında okuma girişimi: VM Adres = 0x{:x}, Boyut = {}, Bellek Boyutu = {}", address, len, self.vm_memory_size);
            Err("Bellek sınırları dışında okuma")
        }
    }

     // VM belleğine belirli bir adrese byte yazma (örnek)
     pub fn write_memory_byte(&mut self, address: u64, value: u8) -> Result<(), LoongArchError> {
         let offset = address as usize;

         if self.vm_memory_ptr.is_null() {
              eprintln!("Hata: VM belleği ayrılmamış, yazma yapılamaz.");
              return Err(LoongArchError::ExecutionError("VM memory not allocated".to_string()));
         }

         // Sınır kontrolü
         if offset < self.vm_memory_size {
             unsafe {
                 // Pointer aritmetiği ile doğru adrese git ve yaz
                 *self.vm_memory_ptr.add(offset) = value;
             }
             Ok(())
         } else {
              eprintln!("Hata: Bellek sınırları dışında yazma girişimi: VM Adres = 0x{:x}, Boyut = {}", address, self.vm_memory_size);
             Err(LoongArchError::MemoryAccessError(address)) // Geçersiz bellek adresi hatası
         }
     }

     // VM belleğinden belirli bir adresten byte okuma (örnek)
     pub fn read_memory_byte(&self, address: u64) -> Result<u8, LoongArchError> {
         let offset = address as usize;

         if self.vm_memory_ptr.is_null() {
              eprintln!("Hata: VM belleği ayrılmamış, okuma yapılamaz.");
               return Err(LoongArchError::ExecutionError("VM memory not allocated".to_string()));
         }

         // Sınır kontrolü
         if offset < self.vm_memory_size {
             unsafe {
                 // Pointer aritmetiği ile doğru adrese git ve oku
                 Ok(*self.vm_memory_ptr.add(offset))
             }
         } else {
              eprintln!("Hata: Bellek sınırları dışında okuma girişimi: VM Adres = 0x{:x}, Boyut = {}", address, self.vm_memory_size);
              Err(LoongArchError::MemoryAccessError(address)) // Geçersiz bellek adresi hatası
         }
     }

    // Register okuma/yazma fonksiyonları
    pub fn get_register(&self, index: usize) -> Result<u64, LoongArchError> {
        if index < 32 {
            Ok(self.registers[index])
        } else {
            eprintln!("Hata: Geçersiz register indeksi: {}", index);
            Err(LoongArchError::ExecutionError(format!("Invalid register index: {}", index)))
        }
    }

    pub fn set_register(&mut self, index: usize, value: u64) -> Result<(), LoongArchError> {
        if index < 32 {
            self.registers[index] = value;
            Ok(())
        } else {
            eprintln!("Hata: Geçersiz register indeksi: {}", index);
            Err(LoongArchError::ExecutionError(format!("Invalid register index: {}", index)))
        }
    }
}
