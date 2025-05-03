use crate::memory as sahne_memory;
use crate::SahneError; // Sahne64 hata türü

use crate::standard_library::StandardLibrary; // StandardLibrary'yi kullanabilmek için

use core::ptr; // İşaretçi operasyonları için
use core::fmt; // Debug ve Display için
use alloc::string::String; // String kullanıldığı için
use alloc::vec::Vec; // Vec kullanıldığı için
use alloc::format; // format! makrosu kullanıldığı için

pub struct RiscvArchitecture {
    // RISC-V mimarisinin iç durumunu tutacak alanlar
    registers: [u64; 32], // RISC-V GPRs (x0-x31), 64-bit (RV64) varsayalım
    pc: u64, // Program Counter (RV64'te u64)
    // Sahne64 tarafından yönetilen VM belleği için pointer ve boyutu
    vm_memory_ptr: *mut u8,
    vm_memory_size: usize,
    // Standard kütüphane instance'ı (VM içindeki guest code tarafından syscall'lar aracılığıyla kullanılır)
    standard_library: StandardLibrary,
    // ... diğer mimariye özgü durumlar (CSRs, FPU registerları vb.) ...
}

// RISC-V VM yürütme hataları
#[derive(Debug)] // fmt::Display de burada derive edilebilir
pub enum RiscvError {
    InvalidInstructionFormat, // Geçersiz komut formatı veya hizalama
    UnsupportedInstruction(u32), // Desteklenmeyen komut (tüm 32-bit word)
    ExecutionError(String),   // Genel yürütme hataları için
    MemoryAccessError(u64), // Geçersiz bellek erişim adresi
    SystemCallError(SahneError), // Sahne64'ten dönen syscall hatası
    // ... diğer hatalar eklenebilir ...
}

// fmt::Display implementasyonu
impl fmt::Display for RiscvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiscvError::InvalidInstructionFormat => write!(f, "Geçersiz Komut Formatı"),
            RiscvError::UnsupportedInstruction(instr) => write!(f, "Desteklenmeyen Komut: 0x{:x}", instr),
            RiscvError::ExecutionError(msg) => write!(f, "Yürütme Hatası: {}", msg),
            RiscvError::MemoryAccessError(address) => write!(f, "Geçersiz Bellek Erişim Adresi: 0x{:x}", address),
            RiscvError::SystemCallError(e) => write!(f, "Sistem Çağrısı Hatası: {:?}", e), // SahneError'ın Debug çıktısını kullan
        }
    }
}

// SahneError'dan RiscvError::SystemCallError'a dönüşüm
impl From<SahneError> for RiscvError {
    fn from(err: SahneError) -> Self {
        RiscvError::SystemCallError(err)
    }
}

// Belleği serbest bırakmak için Drop trait'ini implemente et
impl Drop for RiscvArchitecture {
    fn drop(&mut self) {
         // Eğer belleğe bir işaretçi varsa ve null değilse serbest bırak
         if !self.vm_memory_ptr.is_null() {
             println!("RISC-V VM belleği serbest bırakılıyor (Adres: {:p}, Boyut: {})...", self.vm_memory_ptr, self.vm_memory_size);
              // Sahne64 memory::release fonksiyonunu kullanın
              match sahne_memory::release(self.vm_memory_ptr, self.vm_memory_size) {
                  Ok(_) => println!("RISC-V VM belleği başarıyla serbest bırakıldı."),
                  Err(e) => eprintln!("RISC-V VM belleğini serbest bırakma hatası: {:?}", e),
              }
         }
    }
}


impl RiscvArchitecture {
    /// Yeni bir `RiscvArchitecture` örneği oluşturur ve VM belleğini Sahne64 kullanarak tahsis eder.
    /// Bellek tahsisi başarısız olursa `SahneError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, SahneError> {
         println!("Sahne64 kullanarak {} byte RISC-V VM belleği tahsis ediliyor...", vm_memory_size);
        // Sahne64 memory modülünü kullanarak VM için bellek alanı tahsis et
        let vm_memory_ptr = sahne_memory::allocate(vm_memory_size)?; // sahne_memory::allocate çağrısı, hata Result ile propagate edilir.

         println!("RISC-V VM belleği tahsis edildi: {:p}", vm_memory_ptr);

        Ok(RiscvArchitecture {
            registers: [0; 32], // RISC-V GPRs (x0-x31), 64-bit (RV64)
            pc: 0, // Başlangıç Program Sayacı (genellikle 0 veya entry point adresi)
            vm_memory_ptr,
            vm_memory_size,
            standard_library, // StandardLibrary örneğini al
            // ... diğer durumları başlat (CSRlar vb.) ...
        })
    }

     // Tahsis edilen bellek alanına güvenli erişim için yardımcı fonksiyon
     // VM belleği slice'ını döndürür. İşaretçi null ise panikleyebilir.
     fn get_memory_slice(&mut self) -> &mut [u8] {
         if self.vm_memory_ptr.is_null() {
              // Bellek tahsis hatası sonrası veya Drop sonrası çağrılırsa bu panikleyebilir.
              panic!("Attempted to get memory slice from null VM pointer");
         }
         unsafe { core::slice::from_raw_parts_mut(self.vm_memory_ptr, self.vm_memory_size) }
     }

    // RISC-V komutunu yürütür (PC'deki komutu fetch edip yürütür)
    // signature güncellendi: self artık mutable referans, standard_library field oldu.
    // instruction_bytes parametresi kaldırıldı, bellekten fetch edilecek.
    pub fn execute_next_instruction(&mut self) -> Result<(), RiscvError> {
         let pc = self.pc;
        if pc as usize >= self.vm_memory_size || pc % 4 != 0 {
             // Kod (VM belleğinde olmalı) sınırlarının dışına çıkıldı veya hizalama hatası
             eprintln!("Hata: Geçersiz PC adresi veya hizalama hatası (PC: 0x{:x}, Bellek Boyutu: {})", pc, self.vm_memory_size);
             return Err(RiscvError::MemoryAccessError(pc)); // Veya InvalidInstructionFormat
         }

        // VM belleğinden komut word'ünü oku (RISC-V 32-bit veya 16-bit komutlar)
        // Örnekte 32-bit varsayalım.
        let instruction_bytes_res = self.read_memory_slice(pc, 4); // VM belleğinden 4 byte oku

        let instruction_bytes = match instruction_bytes_res {
            Ok(slice) => {
                if slice.len() < 4 {
                     // read_memory_slice'ın sınır kontrolü yakalamalıydı
                     eprintln!("Hata: Komut fetch sırasında yetersiz byte (PC: 0x{:x})", pc);
                     return Err(RiscvError::InvalidInstructionFormat);
                }
                slice
            },
            Err(e) => {
                 // Bellek okuma hatası (read_memory_slice'dan gelen RiscvError)
                 eprintln!("Hata: Komut fetch sırasında bellek okuma hatası: {}", e);
                 return Err(e); // Hatayı propagate et
            }
        };

        // RISC-V little-endian'dır
         let instruction = u32::from_le_bytes([
             instruction_bytes[0],
             instruction_bytes[1],
             instruction_bytes[2],
             instruction_bytes[3],
         ]);

         // RISC-V komut formatları ve opcode'ları karmaşıktır (opcode, funct3, funct7, rd, rs1, rs2, imm)
         // Ana opcode genellikle alt 7 bittir.
         let opcode = instruction & 0x7F; // Alt 7 bit

         // pc'yi sonraki komuta ilerlet (genellikle 4 byte, compressed ise 2 byte)
         // Bu basit örnekte her zaman 4 byte ilerleyelim.
         self.pc += 4;

        // Opcode'a göre işlemi yönlendir (Çok basitleştirilmiş örnek)
        match opcode {
            0x33 => { // R-type (ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND)
                 println!("[RISC-V] R-Type komutu (opcode: 0x{:02X}) algılandı (PC: 0x{:x}). SIMÜLE EDİLİYOR.", opcode, pc);
                  funct3 ve funct7'ye göre tam komut belirlenir.
                  let funct3 = (instruction >> 12) & 0x7;
                  let funct7 = (instruction >> 25) & 0x7F;
                  let rd = (instruction >> 7) & 0x1F; // Hedef register
                  let rs1 = (instruction >> 15) & 0x1F; // Kaynak register 1
                  let rs2 = (instruction >> 20) & 0x1F; // Kaynak register 2
                 // Örnek ADD (funct3=0x0, funct7=0x00): add rd, rs1, rs2
                  self.set_register(rd as usize, self.get_register(rs1 as usize)? + self.get_register(rs2 as usize)?)?;
                 Ok(()) // SIMÜLE EDİLİYOR
            }
            0x13 => { // I-type (ADDI, SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI, SRAI)
                 println!("[RISC-V] I-Type komutu (opcode: 0x{:02X}) algılandı (PC: 0x{:x}). SIMÜLE EDİLİYOR.", opcode, pc);
                   funct3, rd, rs1, imm12
                   let funct3 = (instruction >> 12) & 0x7;
                   let rd = (instruction >> 7) & 0x1F;
                   let rs1 = (instruction >> 15) & 0x1F;
                   let imm12 = (instruction >> 20); // Immediate 12 bit
                  // Örnek ADDI (funct3=0x0): addi rd, rs1, imm12
                   let immediate = ((imm12 << 20) as i32 >> 20) as u64; // Signed extended imm12 to u64
                   self.set_register(rd as usize, self.get_register(rs1 as usize)? + immediate)?;
                 Ok(()) // SIMÜLE EDİLİYOR
            }
             0x03 => { // I-type (LOAD: LB, LH, LW, LD, LBU, LHU)
                  println!("[RISC-V] LOAD komutu (opcode: 0x{:02X}) algılandı (PC: 0x{:x}). SIMÜLE EDİLİYOR.", opcode, pc);
                   // funct3, rd, rs1, imm12
                    let funct3 = (instruction >> 12) & 0x7; // Byte, Half, Word, Double word vb. belirler
                    let rd = (instruction >> 7) & 0x1F; // Hedef register
                    let rs1 = (instruction >> 15) & 0x1F; // Base register
                    let imm12 = (instruction >> 20); // Immediate 12 bit
                    let offset = ((imm12 << 20) as i32 >> 20); // Signed extended imm12
                    let base_addr = self.get_register(rs1 as usize)?;
                    let effective_address = (base_addr as i64 + offset as i64) as u64; // RV64 adres
                    let value_bytes = self.read_memory_slice(effective_address, /* boyut funct3'e göre */)?;
                   // // Okunan byte'ları rd'ye yaz (boyut ve sign/zero extension'a göre)
                    self.set_register(rd as usize, /* value_bytes'tan çevrilmiş değer */)?;
                  Ok(()) // SIMÜLE EDİLİYOR
             }
             0x23 => { // S-type (STORE: SB, SH, SW, SD)
                  println!("[RISC-V] STORE komutu (opcode: 0x{:02X}) algılandı (PC: 0x{:x}). SIMÜLE EDİLİYOR.", opcode, pc);
                    funct3, rs1, rs2, imm12 (bir kısmı imm[4:0], bir kısmı imm[11:5])
                    let funct3 = (instruction >> 12) & 0x7; // Byte, Half, Word, Double word belirler
                    let rs1 = (instruction >> 15) & 0x1F; // Base register
                    let rs2 = (instruction >> 20) & 0x1F; // Kaynak register (saklanacak değer)
                    let imm12_part1 = (instruction >> 7) & 0x1F; // imm[4:0]
                    let imm12_part2 = (instruction >> 25) & 0x7F; // imm[11:5]
                    let imm12 = (imm12_part2 << 5) | imm12_part1;
                    let offset = ((imm12 << 20) as i32 >> 20); // Signed extended imm12
                    let base_addr = self.get_register(rs1 as usize)?;
                    let effective_address = (base_addr as i64 + offset as i64) as u64; // RV64 adres
                    let value_to_write = self.get_register(rs2 as usize)?;
                   // // Değeri efektif adrese yaz (boyut ve endianness'e göre)
                    self.write_memory_word(effective_address, value_to_write as u32)?; // Örnek: SW için u32 yaz
                  Ok(()) // SIMÜLE EDİLİYOR
             }
             0x73 => { // I-type (CSRRW, CSRRS, CSRRC, CSRRWI, CSRRSI, CSRRCI, URET, SRET, MRET, WFI, EBREAK, ECALL)
                  println!("[RISC-V] ENVIRONMENT komutu (opcode: 0x{:02X}) algılandı (PC: 0x{:x}).", opcode, pc);
                   // funct3 ve diğer bitlere göre alt komutlar belirlenir.
                   let funct3 = (instruction >> 12) & 0x7;
                   let imm12 = (instruction >> 20); // Immediate 12 bit veya CSR adresi

                   match (funct3, imm12) {
                        (0x0, 0x000) => { // ECALL (Environment Call) - RISC-V Syscall
                             println!("  -> ECALL (Syscall) komutu");
                              // Syscall numarası ve argümanlar registerlarda bulunur (RISC-V ABI: a7 numara, a0-a5 args)
                              // a7 = x17, a0-a5 = x10-x15
                              let syscall_num = self.get_register(17)?; // x17 (a7)
                              let args: Vec<u64> = (10..=15).map(|r| self.get_register(r as usize).unwrap_or(0)).collect(); // x10-x15 (a0-a5)

                             // VM içinden gelen bu syscall'u işleyen bir fonksiyon çağır.
                             // Hata dönebilir, bunu yakalayıp RiscvError::SystemCallError'a çeviriyoruz.
                             match self.handle_vm_syscall(syscall_num, &args) {
                                  Ok(return_value) => {
                                       println!("    -> Syscall {} başarıyla işlendi, dönüş değeri: 0x{:x}", syscall_num, return_value);
                                      // Syscall dönüş değerini registera yaz (RISC-V a0 = x10)
                                      self.set_register(10, return_value)?;
                                       // Hata bayrağını (varsa) temizle (RISC-V'de genellikle a1'e hata kodu yazılır)
                                      self.set_register(11, 0)?; // x11 (a1)
                                  },
                                  Err(e) => {
                                       eprintln!("    -> Syscall {} işleme hatası: {:?}", syscall_num, e);
                                       // Hata durumunda dönüş değerini (genellikle -1) a0'a yaz ve hata kodunu a1'e yaz (RISC-V convention)
                                        self.set_register(10, (-1i64) as u64)?; // x10 (a0) = -1
                                       let vm_errno = map_sahne_error_to_vm_errno(&e.into_sahne_error().unwrap_or(SahneError::UnknownSystemCall)); // SahneError'dan errno'ya çevir
                                        self.set_register(11, vm_errno as u64)?; // x11 (a1) = errno
                                  }
                             }
                             Ok(()) // Ecall komutu yürütüldü
                        }
                        (0x0, 0x001) => { // EBREAK (Environment Breakpoint)
                             println!("  -> EBREAK (Breakpoint) komutu");
                             // Hata ayıklayıcıya veya VM runner'a kontrolü devret
                             Err(RiscvError::ExecutionError("Breakpoint reached".to_string()))
                        }
                        // ... MRET, SRET, URET, WFI, CSRR* komutları ...
                        _ => {
                            eprintln!("  -> Bilinmeyen ENVIRONMENT alt komutu (funct3: 0x{:x}, imm12: 0x{:x})", funct3, imm12);
                            Err(RiscvError::UnsupportedInstruction(instruction))
                        }
                   }
             }
             // ... diğer ana opcode'lar ...
            _ => {
                eprintln!("[RISC-V] Bilinmeyen ana opcode: 0x{:02X} (instruction: 0x{:x}, PC: 0x{:x})", opcode, instruction, pc);
                Err(RiscvError::UnsupportedInstruction(instruction))
            }
        }
    }

    // VM içinden gelen gerçek syscall'ları işleyen fonksiyon (Sahne64 API'sını kullanır)
    // Dönüş değeri (u64) genellikle a0 (x10) registerına yazılır.
    // Hata durumunda Err(RiscvError) döner (syscall sırasında Sahne64 hatası olabilir).
    // args: a0-a5 (x10-x15) registerlarının değerleri
    fn handle_vm_syscall(&mut self, syscall_num: u64, args: &[u64]) -> Result<u64, RiscvError> {
        println!("  -> RISC-V VM Syscall işleniyor: {}", syscall_num);
        // Syscall numarasına göre Sahne64 API fonksiyonlarını çağır
        // args slice'ı VM registerlarındaki argümanları temsil eder (a0-a5 / x10-x15).
        // RISC-V syscall convention'ı: a0-a5 6 argüman, a7 syscall numarası.
        // Sahne64 API'sında argümanlar u64 olarak geçiyor.

        match syscall_num {
            // Örnek: Sahne64 task::exit syscall'u (VM_SYSCALL_EXIT = 4 olsun)
            93 => { // RISC-V Newlib/Linux ABI: exit
                 // Çıkış kodu a0'da (args[0])
                 let exit_code = args[0] as i32; // args[0] == a0 (x10)
                 println!("    -> VM Syscall: exit({}) çağrısı simüle ediliyor.", exit_code);
                 // task::exit fonksiyonu geri dönmez, bu fonksiyon da geri dönmemeli veya özel bir durum bildirmeli
                 // Eğer task::exit çağrılırsa, buradan geri dönülmez.
                 // return task::exit(exit_code); // Bu doğru kullanım olurdu.
                 Ok(0) // Simülasyon için başarı dönelim.
            }
             // Örnek: Sahne64 resource::write syscall'u (VM_SYSCALL_WRITE = 7 olsun)
             64 => { // RISC-V Newlib/Linux ABI: write
                  // Argümanlar (RISC-V ABI): a0 (x10) -> Handle, a1 (x11) -> buffer adresi, a2 (x12) -> buffer boyutu
                   args slice'ı: args[0]=a0, args[1]=a1, args[2]=a2
                   let handle_raw = args[0];
                   let vm_buffer_addr = args[1]; // RISC-V 64-bit adres
                   let size = args[2] as usize;

                   println!("    -> VM Syscall: resource::write çağrısı simüle ediliyor. Handle: {}, VM Adres: 0x{:x}, Boyut: {}", handle_raw, vm_buffer_addr, size);

                   // VM belleğindeki buffer'a erişmek için slice al
                   // Sınır kontrolünü yap!
                   if vm_buffer_addr as usize + size > self.vm_memory_size {
                        eprintln!("    -> Hata: resource::write Syscall: Bellek sınırları dışında buffer (VM Adres: 0x{:x}, Boyut: {}, Bellek Boyutu: {})", vm_buffer_addr, size, self.vm_memory_size);
                         // SahneError::InvalidAddress gibi bir hataya çevirelim
                         return Err(RiscvError::SystemCallError(SahneError::InvalidAddress));
                   }
                   let vm_memory_slice = self.get_memory_slice(); // Mutable slice alır
                   let buffer_slice = &vm_memory_slice[vm_buffer_addr as usize .. (vm_buffer_addr as usize) + size];

                   // Handle'ı Sahne64 Handle struct'ına çevir
                   let sahne64_handle = crate::Handle(handle_raw);

                   // Sahne64 resource::write çağrısı yap
                   match crate::resource::write(sahne64_handle, buffer_slice) {
                       Ok(bytes_written) => {
                            // Başarı durumunda yazılan byte sayısını dön
                            Ok(bytes_written as u64) // Dönüş değeri 64-bit
                       }
                       Err(e) => {
                            // SahneError'ı propagate et (From implementasyonu kullanır)
                            Err(e.into()) RiscvError::SystemCallError(e)
                       }
                   }
             }
            // ... diğer VM syscall'ları için eşleşmeler ...
            // Örnek: read (63), openat (56), close (57), fstat (80), exit_group (94) vb.
             // Sahne64 API'sına karşılık gelenler implemente edilir.
            _ => {
                eprintln!("  -> Bilinmeyen RISC-V VM syscall: {}", syscall_num);
                // SahneError::NotSupported gibi bir hataya çevirelim
                Err(RiscvError::SystemCallError(SahneError::NotSupported))
            }
        }
        // Bu fonksiyonun dönüş değeri (Ok(value)) VM registerlarına yazılır (a0).
        // Hata durumunda (Err(e)) ise VM registerlarına hata kodu yazılır (a0 = -1, a1 = errno).
    }


    // VM belleğinden belirli bir adresten slice okuma (read-only)
    // instruction fetch veya veri yükleme için kullanılır.
    // address u64
    fn read_memory_slice(&self, address: u64, len: usize) -> Result<&[u8], RiscvError> {
        let offset = address as usize;

         // Bellek pointerı geçerli mi kontrol et
         if self.vm_memory_ptr.is_null() {
              eprintln!("Hata: VM belleği ayrılmamış, okuma yapılamaz.");
              return Err(RiscvError::ExecutionError("VM memory not allocated".to_string()));
         }

        // Sınır kontrolü
        if offset < self.vm_memory_size && offset + len <= self.vm_memory_size {
             // Read-only slice al (get_memory_slice mut döndürdüğü için burada raw pointer kullanmak daha doğru)
             let vm_memory = unsafe { core::slice::from_raw_parts(self.vm_memory_ptr, self.vm_memory_size) };
             Ok(&vm_memory[offset .. offset + len])
        } else {
             eprintln!("Hata: Bellek sınırları dışında okuma girişimi: VM Adres = 0x{:x}, Boyut = {}, Bellek Boyutu = {}", address, len, self.vm_memory_size);
            Err(RiscvError::MemoryAccessError(address)) // Geçersiz bellek adresi hatası
        }
    }

     // VM belleğine belirli bir adrese word (4 byte) yazma (örnek SW)
     // address u64, value u32 (RV32/RV64'te word 32-bit)
     pub fn write_memory_word(&mut self, address: u64, value: u32) -> Result<(), RiscvError> {
         let offset = address as usize;
         let len = 4; // Word boyutu

         if self.vm_memory_ptr.is_null() {
              eprintln!("Hata: VM belleği ayrılmamış, yazma yapılamaz.");
              return Err(RiscvError::ExecutionError("VM memory not allocated".to_string()));
         }
         if address % 4 != 0 {
              eprintln!("Hata: Hizalama hatası (word yazma): VM Adres = 0x{:x}", address);
              return Err(RiscvError::MemoryAccessError(address)); // Hizalama hatası bellek erişim hatasıdır.
         }

         // Sınır kontrolü
         if offset < self.vm_memory_size && offset + len <= self.vm_memory_size {
             unsafe {
                 // Pointer aritmetiği ile doğru adrese git ve yaz
                 // RISC-V little-endian
                 let value_bytes = value.to_le_bytes();
                  let vm_memory = core::slice::from_raw_parts_mut(self.vm_memory_ptr, self.vm_memory_size);
                  vm_memory[offset .. offset + len].copy_from_slice(&value_bytes);
             }
             Ok(())
         } else {
              eprintln!("Hata: Bellek sınırları dışında yazma girişimi (word): VM Adres = 0x{:x}, Boyut = {}, Bellek Boyutu = {}", address, len, self.vm_memory_size);
             Err(RiscvError::MemoryAccessError(address)) // Geçersiz bellek adresi hatası
         }
     }

     // VM belleğinden belirli bir adresten word (4 byte) okuma (örnek LW)
     // address u64, dönüş u32
     pub fn read_memory_word(&self, address: u64) -> Result<u32, RiscvError> {
         let offset = address as usize;
         let len = 4; // Word boyutu

         if self.vm_memory_ptr.is_null() {
              eprintln!("Hata: VM belleği ayrılmamış, okuma yapılamaz.");
               return Err(RiscvError::ExecutionError("VM memory not allocated".to_string()));
         }
         if address % 4 != 0 {
              eprintln!("Hata: Hizalama hatası (word okuma): VM Adres = 0x{:x}", address);
              return Err(RiscvError::MemoryAccessError(address)); // Hizalama hatası bellek erişim hatasıdır.
         }

         // Sınır kontrolü
         if offset < self.vm_memory_size && offset + len <= self.vm_memory_size {
             unsafe {
                 // Pointer aritmetiği ile doğru adrese git ve oku
                 // RISC-V little-endian
                  let vm_memory = core::slice::from_raw_parts(self.vm_memory_ptr, self.vm_memory_size);
                  let value_bytes: [u8; 4] = vm_memory[offset .. offset + len].try_into().unwrap(); // Sınır kontrolü yapıldı
                 Ok(u32::from_le_bytes(value_bytes))
             }
         } else {
              eprintln!("Hata: Bellek sınırları dışında okuma girişimi (word): VM Adres = 0x{:x}, Boyut = {}, Bellek Boyutu = {}", address, len, self.vm_memory_size);
              Err(RiscvError::MemoryAccessError(address)) // Geçersiz bellek adresi hatası
         }
     }

    // Register okuma/yazma fonksiyonları
    pub fn get_register(&self, index: usize) -> Result<u64, RiscvError> { // u64 registerlar
        if index < 32 {
            Ok(self.registers[index])
        } else {
            eprintln!("Hata: Geçersiz register indeksi: {}", index);
            Err(RiscvError::ExecutionError(format!("Invalid register index: {}", index)))
        }
    }

    pub fn set_register(&mut self, index: usize, value: u64) -> Result<(), RiscvError> { // u64 registerlar
        if index < 32 {
            self.registers[index] = value;
            Ok(())
        } else {
            eprintln!("Hata: Geçersiz register indeksi: {}", index);
            Err(RiscvError::ExecutionError(format!("Invalid register index: {}", index)))
        }
    }

    // RISC-V ABI'sında kullanılan errno değerlerini SahneError'a çevirme (örnek)
    // Gerçek implementasyon SahneError'ları VM'in beklediği errno değerlerine çevirir.
    // Bu fonksiyon handle_vm_syscall içindeki Err dönüşünden sonra kullanılır.
    fn map_sahne_error_to_vm_errno(&self, error: &SahneError) -> i32 {
        match error {
            SahneError::PermissionDenied => 1, // EPERM
            SahneError::ResourceNotFound => 2, // ENOENT
            SahneError::InvalidParameter => 22, // EINVAL
            SahneError::OutOfMemory => 12, // ENOMEM
            SahneError::InvalidAddress => 14, // EFAULT
            SahneError::NotSupported => 38, // ENOSYS
            SahneError::ResourceBusy => 11, // EAGAIN veya EBUSY (errno farklı olabilir)
            SahneError::Interrupted => 4, // EINTR
            SahneError::NoMessage => 61, // ENOMSG
            SahneError::InvalidOperation => 95, // EOPNOTSUPP veya EBADFD (errno farklı olabilir)
            // ... diğer eşlemeler ...
            _ => 255, // Genel hata veya bilinmeyen (EMISC veya özel Sahne64 errno)
        }
    }

    // SahneError'ı Unpack etmek için yardımcı fonksiyon (From implementasyonu ile kullanışlı)
     fn into_sahne_error(self) -> Option<SahneError> {
         match self {
             RiscvError::SystemCallError(e) => Some(e),
             _ => None,
         }
     }
}
