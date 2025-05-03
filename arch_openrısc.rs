use crate::memory as sahne_memory;
use crate::SahneError; // Sahne64 hata türü

use crate::standard_library::StandardLibrary; // StandardLibrary'yi kullanabilmek için

use core::ptr; // İşaretçi operasyonları için
use core::fmt; // Debug ve Display için
use alloc::string::String; // String kullanıldığı için
use alloc::vec::Vec; // Vec kullanıldığı için
use alloc::format; // format! makrosu kullanıldığı için

pub struct OpenriscArchitecture {
    // OpenRISC mimarisinin iç durumunu tutacak alanlar
    registers: [u32; 32], // OpenRISC genel amaçlı registerları (GPRs)
    pc: u32, // Program Counter
    // Sahne64 tarafından yönetilen VM belleği için pointer ve boyutu
    vm_memory_ptr: *mut u8,
    vm_memory_size: usize,
    // Standard kütüphane instance'ı (VM içindeki guest code tarafından syscall'lar aracılığıyla kullanılır)
    standard_library: StandardLibrary,
    // ... diğer mimariye özgü durumlar (SPRler, Exception state vb.) ...
}

// OpenRISC VM yürütme hataları
#[derive(Debug)] // fmt::Display de burada derive edilebilir
pub enum OpenriscError {
    InvalidInstructionFormat, // Geçersiz komut formatı
    UnsupportedOpcode(u32), // Desteklenmeyen ana opcode
    ExecutionError(String),   // Genel yürütme hataları için
    MemoryAccessError(u32), // Geçersiz bellek erişim adresi (u32 olarak)
    SystemCallError(SahneError), // Sahne64'ten dönen syscall hatası
    // ... diğer hatalar eklenebilir ...
}

// fmt::Display implementasyonu
impl fmt::Display for OpenriscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenriscError::InvalidInstructionFormat => write!(f, "Geçersiz Komut Formatı"),
            OpenriscError::UnsupportedOpcode(opcode) => write!(f, "Desteklenmeyen Ana Opcode: 0x{:x}", opcode),
            OpenriscError::ExecutionError(msg) => write!(f, "Yürütme Hatası: {}", msg),
            OpenriscError::MemoryAccessError(address) => write!(f, "Geçersiz Bellek Erişim Adresi: 0x{:x}", address),
            OpenriscError::SystemCallError(e) => write!(f, "Sistem Çağrısı Hatası: {:?}", e), // SahneError'ın Debug çıktısını kullan
        }
    }
}

// SahneError'dan OpenriscError::SystemCallError'a dönüşüm
impl From<SahneError> for OpenriscError {
    fn from(err: SahneError) -> Self {
        OpenriscError::SystemCallError(err)
    }
}

// std::error::Error trait implementasyonu no_std ortamında std feature gerektirir.
// Eğer std feature yoksa bu kısım koşullu derlenmelidir.
 #[cfg(feature = "std")]
 impl std::error::Error for OpenriscError {}


// Belleği serbest bırakmak için Drop trait'ini implemente et
impl Drop for OpenriscArchitecture {
    fn drop(&mut self) {
         // Eğer belleğe bir işaretçi varsa ve null değilse serbest bırak
         if !self.vm_memory_ptr.is_null() {
             println!("OpenRISC VM belleği serbest bırakılıyor (Adres: {:p}, Boyut: {})...", self.vm_memory_ptr, self.vm_memory_size);
              // Sahne64 memory::release fonksiyonunu kullanın
              match sahne_memory::release(self.vm_memory_ptr, self.vm_memory_size) {
                  Ok(_) => println!("OpenRISC VM belleği başarıyla serbest bırakıldı."),
                  Err(e) => eprintln!("OpenRISC VM belleğini serbest bırakma hatası: {:?}", e),
              }
         }
    }
}


impl OpenriscArchitecture {
    /// Yeni bir `OpenriscArchitecture` örneği oluşturur ve VM belleğini Sahne64 kullanarak tahsis eder.
    /// Bellek tahsisi başarısız olursa `SahneError` döner.
    /// HardwareAbstraction kaldırıldı, bellek doğrudan bu struct içinde yönetilir.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, SahneError> {
         println!("Sahne64 kullanarak {} byte OpenRISC VM belleği tahsis ediliyor...", vm_memory_size);
        // Sahne64 memory modülünü kullanarak VM için bellek alanı tahsis et
        let vm_memory_ptr = sahne_memory::allocate(vm_memory_size)?; // sahne_memory::allocate çağrısı, hata Result ile propagate edilir.

         println!("OpenRISC VM belleği tahsis edildi: {:p}", vm_memory_ptr);

        Ok(OpenriscArchitecture {
            registers: [0; 32], // OpenRISC GPRs (R0-R31), 32-bit
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
              // Bellek tahsis hatası sonrası veya Drop sonrası çağrılırsa bu panikleyebilir.
              panic!("Attempted to get memory slice from null VM pointer");
         }
         unsafe { core::slice::from_raw_parts_mut(self.vm_memory_ptr, self.vm_memory_size) }
     }

    // OpenRISC komutunu yürütür.
    // signature güncellendi: self artık mutable referans, standard_library field oldu.
    // instruction_bytes yerine VM belleğindeki PC'den instruction fetch edilecek.
    // HardwareAbstraction kaldırıldı, bellek erişimi doğrudan yapılır.
    pub fn execute_next_instruction(&mut self) -> Result<(), OpenriscError> {
         let pc = self.pc;
        if pc as usize >= self.vm_memory_size {
             // Kod (VM belleğinde olmalı) sınırlarının dışına çıkıldı
             eprintln!("Hata: VM belleği sınırının dışına çıkıldı (PC: 0x{:x}, Bellek Boyutu: {})", pc, self.vm_memory_size);
             return Err(OpenriscError::ExecutionError(format!("PC out of bounds: 0x{:x}", pc)));
         }

        // VM belleğinden komut baytlarını oku (OpenRISC genellikle 32-bit komutlar kullanır)
        let instruction_bytes_res = self.read_memory_slice(pc, 4); // VM belleğinden 4 byte oku

        let instruction_bytes = match instruction_bytes_res {
            Ok(slice) => {
                if slice.len() < 4 {
                     // Bu durum read_memory_slice'ın sınır kontrolü ile yakalanmalıydı
                     eprintln!("Hata: Komut fetch sırasında yetersiz byte (PC: 0x{:x})", pc);
                     return Err(OpenriscError::InvalidInstructionFormat);
                }
                slice
            },
            Err(e) => {
                 // Bellek okuma hatası (read_memory_slice'dan gelen OpenriscError)
                 eprintln!("Hata: Komut fetch sırasında bellek okuma hatası: {}", e);
                 return Err(e); // read_memory_slice artık OpenriscError dönüyor
            }
        };


        // OpenRISC komut formatı genellikle 32-bit, farklı formatlar var (I, J, R, K, L, M, N, O)
        // Komut baytlarını u32'ye çevir (OpenRISC big-endian'dır)
         let instruction = u32::from_be_bytes([ // OpenRISC big-endian
             instruction_bytes[0],
             instruction_bytes[1],
             instruction_bytes[2],
             instruction_bytes[3],
         ]);

        let opcode = (instruction >> 26) & 0x3F; // İlk 6 bit ana opcode


        // Opcode'a göre işlem yap (Örnek opcode işleme)
        match opcode {
            0x01 => { // l.nop
                println!("[OpenRISC] l.nop komutu yürütülüyor (PC: 0x{:x}).", pc);
                self.pc += 4; // PC'yi ilerlet (OpenRISC komutları 4 byte)
                Ok(())
            }
            0x02 => { // l.lwz (Load Word and Zero) - Load komutu
                 println!("[OpenRISC] l.lwz komutu algılandı (PC: 0x{:x}).", pc);
                 // Komut formatı: opcode:6 | rA:5 | rB:5 | rD:5 | imm16:16 (Bazı formatlar farklı)
                  lwz rD, imm16(rA)
                 // instruction = opcode | rA | rB | rD | imm16 (bits kaydırılmış)
                 let ra = (instruction >> 21) & 0x1F; // Register A
                 let rd = (instruction >> 16) & 0x1F; // Register D (Target)
                 let imm16 = (instruction & 0xFFFF) as u16; // Immediate 16 bit

                 // Adresi hesapla: Base Register rA + signed extended imm16
                 let base_addr = self.get_register(ra as usize)?;
                 // imm16 signed extended olmalı
                 let offset = (imm16 as i16) as i32; // i16 to i32 (signed extended)
                 let effective_address = (base_addr as i32 + offset) as u32; // VM adres alanı içinde

                 println!("  -> l.lwz r{:}, {:}(r{:}), Adres: 0x{:x}", rd, offset, ra, effective_address);

                 // VM belleğinden kelime (4 byte) oku
                 let value_bytes_res = self.read_memory_slice(effective_address, 4); // 4 byte oku

                 match value_bytes_res {
                      Ok(value_slice) => {
                           // OpenRISC big-endian
                           let value = u32::from_be_bytes([value_slice[0], value_slice[1], value_slice[2], value_slice[3]]);
                           println!("  -> Okunan değer: 0x{:x}", value);
                           // Değeri hedef registera yaz
                           self.set_register(rd as usize, value)?;
                           self.pc += 4; // PC'yi ilerlet
                           Ok(())
                      }
                      Err(e) => {
                           // Bellek okuma hatası (read_memory_slice'dan gelen OpenriscError)
                           eprintln!("  -> Hata: l.lwz sırasında bellek okuma hatası: {}", e);
                            self.pc += 4; // Hata durumunda PC'yi ilerletmek yaygın
                           Err(e) // Hatayı propagate et
                      }
                 }
             }
             0x04 => { // l.sw (Store Word) - Store komutu
                  println!("[OpenRISC] l.sw komutu algılandı (PC: 0x{:x}).", pc);
                  // Komut formatı: opcode:6 | rA:5 | rB:5 | rS:5 | imm16:16 (rB yerine rS)
                   sw rS, imm16(rA)
                  // instruction = opcode | rA | rB | rS | imm16 (bits kaydırılmış)
                  let ra = (instruction >> 21) & 0x1F; // Register A (Base)
                  let rs = (instruction >> 16) & 0x1F; // Register S (Source)
                  let imm16 = (instruction & 0xFFFF) as u16; // Immediate 16 bit

                   // Adresi hesapla: Base Register rA + signed extended imm16
                  let base_addr = self.get_register(ra as usize)?;
                  let offset = (imm16 as i16) as i32; // i16 to i32 (signed extended)
                  let effective_address = (base_addr as i32 + offset) as u32; // VM adres alanı içinde

                   // Saklanacak değeri kaynak register rS'den al
                   let value_to_write = self.get_register(rs as usize)?;
                   println!("  -> l.sw r{:}, {:}(r{:}), Adres: 0x{:x}, Yazılacak Değer: 0x{:x}", rs, offset, ra, effective_address, value_to_write);


                  // VM belleğine kelime (4 byte) yaz
                  let value_bytes = value_to_write.to_be_bytes(); // OpenRISC big-endian
                  let write_res = self.write_memory_slice(effective_address, &value_bytes); // 4 byte yaz

                  match write_res {
                       Ok(_) => {
                            self.pc += 4; // PC'yi ilerlet
                            Ok(())
                       }
                       Err(e) => {
                            // Bellek yazma hatası (write_memory_slice'dan gelen OpenriscError)
                            eprintln!("  -> Hata: l.sw sırasında bellek yazma hatası: {}", e);
                             self.pc += 4; // Hata durumunda PC'yi ilerletmek yaygın
                            Err(e) // Hatayı propagate et
                       }
                  }
             }
             0x11 => { // l.jal (Jump and Link) - Zıplama komutu
                  println!("[OpenRISC] l.jal komutu algılandı (PC: 0x{:x}).", pc);
                   // Komut formatı: opcode:6 | L:1 | imm25:25
                   // L bit'i 1 ise PC + 8 (delay slot sonrası) r9'a kaydedilir (return address register)
                   let l_bit = (instruction >> 25) & 0x1; // L bit
                   let imm25 = instruction & 0x1FFFFFF; // Immediate 25 bit

                   // Zıplama adresi: PC (mevcut komutun başlangıcı) + signed extended imm25 << 2
                   // OpenRISC pipeline'ı nedeniyle PC genellikle mevcut + 4'tür.
                   // Zıplama hedefi genellikle (PC + 4) + signed_extended_imm25 * 4
                   // Veya l.jal için hedef 32-bit adresin 2'ye bölünmüş hali immediate içinde? (MIPS J gibi)
                   // OpenRISC spec'e göre imm25 * 4 + PC & 0xFFFFFFFC.
                   let target_address = ((imm25 << 2) as i32).wrapping_add(pc as i32 & 0xFFFFFFFC) as u32; // İşaretli ekleme ve PC hizalama


                   if l_bit == 1 {
                       // Return address'i (PC + 8) r9'a kaydet (delay slot nedeniyle)
                        let return_address = pc.wrapping_add(8); // PC + 8
                       self.set_register(9, return_address)?; // r9
                       println!("  -> Return address (0x{:x}) r9'a kaydedildi.", return_address);
                   }

                   // PC'yi hedef adrese ayarla
                   self.pc = target_address;
                   println!("  -> l.jal ile 0x{:x} adresine zıplanıyor (L bit: {}).", target_address, l_bit);

                   // !!! OpenRISC DELAY SLOT'a sahiptir!
                   // l.jal'den sonraki komut (PC+4'teki) yürütülür, sonra PC zıplama adresine gider.
                   // Emülatörde bu, bir sonraki execute_next_instruction çağrısında PC+4'teki komutun
                   // yürütüleceği, bir sonraki çağrıda ise PC'nin target_address'e ayarlanacağı anlamına gelir.
                   // Bu basit örnekte delay slot simüle EDİLMİYOR.
                   // PC'yi doğrudan target_address'e ayarlamak yanlış simülasyon olur.
                   // Delay slot yönetimi için emülatörün state'ine ek bilgi (örn: next_pc) eklenmelidir.
                   // Şimdilik, delay slot'u yoksayarak PC'yi doğrudan atlayalım.
                   // self.pc += 4; // Normal PC artışı (delay slot'u yoksayarak)
                   // Ardından bir sonraki cycle'da PC target_address olacak...
                   // Bu basitleştirilmiş örnekte PC'yi doğrudan ayarlamak yerine,
                   // yürütme döngüsünün PC'yi instruction_len kadar artırmasını ve
                   // dallanma/zıplama komutlarının PC'yi *sonraki* cycle için ayarlamasını bekleyelim.
                   // O zaman burası sadece bir state güncellemesi yapar.
                    self.next_pc = target_address; // Delay slot simülasyonu olsaydı

                   // Delay slot'u yoksayarak basit zıplama:
                   // self.pc = target_address; // DOĞRU SİMÜLASYON DEĞİL ama basitleştirilmiş örnek
                   // Basitlik için bu örnekte PC'yi manuel ilerletmiyoruz, PC PC += 4 ile artacak,
                   // bu komut sadece register'ı güncelleyip 'zıplama' yapacakmış gibi çıktı verir.
                   // Gerçek emülatörde burası PC akışını ciddi şekilde değiştirir.
                   // Emülatörün döngüsü PC'yi ne zaman güncelleyeceğine karar verir.
                   // Bu örnekte execute_next_instruction sonunda PC+=4 yapılıyorsa, zıplama adresine gitmek için
                   // o artışı iptal edip target_address'e ayarlamak gerekir.
                    self.pc = target_address - 4; // Sonraki PC+=4 ile target_address'e ulaşsın.
                   self.pc = target_address; // Şimdilik direkt atama yapalım (delay slot'u tamamen yoksayarak en basit simülasyon)

                   Ok(())
             }
             0x21 => { // l.sys (System Call) - Syscall komutu
                  println!("[OpenRISC] l.sys komutu algılandı (PC: 0x{:x}).", pc);
                  // l.sys komutu formatı: opcode:6 | imm26:26
                  // imm26 genellikle syscall numarasını taşır.
                  let syscall_num = instruction & 0x3FFFFFF; // alt 26 bit

                   println!("  -> Syscall Numarası: {}", syscall_num);

                  // VM içinden gelen bu syscall'u işleyen bir fonksiyon çağır.
                  // Argümanlar registerlarda bulunur (OpenRISC ABI'sına göre: r3-r8)
                   let args = &[self.registers[3], self.registers[4], ... self.registers[8]];
                   let args: Vec<u64> = (3..=8).map(|r| self.registers[r] as u64).collect(); // r3'ten r8'e argümanları al

                  // Hata dönebilir, bunu yakalayıp OpenriscError::SystemCallError'a çeviriyoruz.
                  match self.handle_vm_syscall(syscall_num as u64, &args) {
                       Ok(return_value) => {
                            println!("  -> Syscall {} başarıyla işlendi, dönüş değeri: 0x{:x}", syscall_num, return_value);
                            // Syscall dönüş değerini registera yaz (OpenRISC'te genellikle r3)
                            self.registers[3] = return_value as u32; // r3 32-bit
                            // Hata bayrağını (varsa) temizle (örn: r4 = 0)
                             self.registers[4] = 0; // r4 de 32-bit
                       },
                       Err(e) => {
                            eprintln!("  -> Syscall {} işleme hatası: {:?}", syscall_num, e);
                            // Hata kodunu registera yaz (örn: r3 = -EFAULT, r4 = hata numarası)
                            // OpenRISC ABI'sında hata kodu genellikle r3'e yazılır ve r4'e bir flag konur.
                            // errno değeri r3'e, hata flag'i r4'e (non-zero) konur.
                             self.registers[3] = (-1i32) as u32; // Genel hata dönüş değeri
                            // SahneError'ı VM'in hata koduna çevirmek gerekebilir.
                             let vm_errno = map_sahne_error_to_vm_errno(e); // Özel çevrim fonksiyonu
                             self.registers[3] = vm_errno as u32;
                            self.registers[4] = 1; // Hata bayrağı set edildi (non-zero)
                       }
                  }

                  self.pc += 4; // PC'yi ilerlet
                  Ok(())
             }
            // ... diğer opcode'lar için case'ler ...
            _ => {
                eprintln!("[OpenRISC] Bilinmeyen ana opcode: 0x{:x} (PC: 0x{:x})", opcode, pc);
                 self.pc += 4; // Bilinmeyen komutta bile PC'yi ilerletmek yaygın (ama istisna da olabilir)
                Err(OpenriscError::UnsupportedOpcode(opcode as u32)) // Bilinmeyen opcode hatası
            }
        }
    }

    // VM içinden gelen gerçek syscall'ları işleyen fonksiyon (Sahne64 API'sını kullanır)
    // Dönüş değeri (u64) genellikle r3 registerına yazılır (32-bit'e cast edilir).
    // Hata durumunda Err(OpenriscError) döner (syscall sırasında Sahne64 hatası olabilir).
    // args: r3-r8 registerlarının değerleri
    fn handle_vm_syscall(&mut self, syscall_num: u64, args: &[u64]) -> Result<u64, OpenriscError> {
        println!("  -> OpenRISC VM Syscall işleniyor: {}", syscall_num);
        // Syscall numarasına göre Sahne64 API fonksiyonlarını çağır
        // args slice'ı VM registerlarındaki argümanları temsil eder (r3-r8).
        match syscall_num {
            // Örnek: Sahne64 task::exit syscall'u (VM_SYSCALL_EXIT = 4 olsun)
            4 => { // Syscall 4: Exit
                 // Çıkış kodu r3'te olsun (args[0])
                  let exit_code = args[0] as i32; // args[0] == r3 (casted to u64)
                 // task::exit fonksiyonu geri dönmez, bu fonksiyon da geri dönmemeli veya özel bir durum bildirmeli
                 // Şimdilik sadece çıktı verelim ve Ok(0) dönelim (gerçekçi değil)
                 println!("    -> VM Syscall: task::exit çağrısı simüle ediliyor.");
                  task::exit(exit_code); // Gerçekte bu satır çağrılır ve geri dönmez
                 Ok(0) // Başarı değeri
            }
             // Örnek: Sahne64 resource::write syscall'u (VM_SYSCALL_WRITE = 7 olsun)
             7 => { Syscall 7: Write
                  // Argümanlar (OpenRISC ABI): r3 -> Handle, r4 -> buffer adresi, r5 -> buffer boyutu
                   args slice'ı: args[0]=r3, args[1]=r4, args[2]=r5
                   let handle_raw = args[0];
                   let vm_buffer_addr = args[1] as u32; // OpenRISC adresleri 32-bit
                   let size = args[2] as usize;

                   println!("    -> VM Syscall: resource::write çağrısı simüle ediliyor. Handle: {}, VM Adres: 0x{:x}, Boyut: {}", handle_raw, vm_buffer_addr, size);


                   // VM belleğindeki buffer'a erişmek için slice al
                   // Sınır kontrolünü yap!
                   if vm_buffer_addr as usize + size > self.vm_memory_size {
                        eprintln!("    -> Hata: resource::write Syscall: Bellek sınırları dışında buffer (VM Adres: 0x{:x}, Boyut: {}, Bellek Boyutu: {})", vm_buffer_addr, size, self.vm_memory_size);
                         // SahneError::InvalidAddress gibi bir hataya çevirelim
                         return Err(OpenriscError::SystemCallError(SahneError::InvalidAddress));
                   }
                   let vm_memory_slice = self.get_memory_slice(); // Mutable slice alır
                   let buffer_slice = &vm_memory_slice[vm_buffer_addr as usize .. (vm_buffer_addr as usize) + size];

                   // Handle'ı Sahne64 Handle struct'ına çevir
                   let sahne64_handle = crate::Handle(handle_raw);

                   // Sahne64 resource::write çağrısı yap
                   match crate::resource::write(sahne64_handle, buffer_slice) {
                       Ok(bytes_written) => {
                            // Başarı durumunda yazılan byte sayısını dön
                            Ok(bytes_written as u64) // OpenRISC r3 32-bit ama syscall dönüşü 64-bit dönebilir
                       }
                       Err(e) => {
                            // SahneError'ı propagate et (From implementasyonu kullanır)
                            Err(e.into()) OpenriscError::SystemCallError(e)
                       }
                   }
             }
            // ... diğer VM syscall'ları için eşleşmeler ...
            // Örnek: read, open, close, allocate, spawn_task, sleep vb.
            _ => {
                eprintln!("  -> Bilinmeyen OpenRISC VM syscall: {}", syscall_num);
                // SahneError::NotSupported gibi bir hataya çevirelim
                Err(OpenriscError::SystemCallError(SahneError::NotSupported))
            }
        }
        // Bu fonksiyonun dönüş değeri (Ok(value)) VM registerlarına yazılır.
        // Hata durumunda (Err(e)) ise VM registerlarına hata kodu yazılır ve/veya bayrak set edilir.
    }


    // VM belleğinden belirli bir adresten slice okuma (read-only)
    // instruction fetch veya veri yükleme için kullanılır.
    fn read_memory_slice(&self, address: u32, len: usize) -> Result<&[u8], OpenriscError> { // address u32
        let offset = address as usize;

         // Bellek pointerı geçerli mi kontrol et
         if self.vm_memory_ptr.is_null() {
              eprintln!("Hata: VM belleği ayrılmamış, okuma yapılamaz.");
              return Err(OpenriscError::ExecutionError("VM memory not allocated".to_string()));
         }

        // Sınır kontrolü
        if offset < self.vm_memory_size && offset + len <= self.vm_memory_size {
             // Read-only slice al (get_memory_slice mut döndürdüğü için burada raw pointer kullanmak daha doğru)
             let vm_memory = unsafe { core::slice::from_raw_parts(self.vm_memory_ptr, self.vm_memory_size) };
             Ok(&vm_memory[offset .. offset + len])
        } else {
             eprintln!("Hata: Bellek sınırları dışında okuma girişimi: VM Adres = 0x{:x}, Boyut = {}, Bellek Boyutu = {}", address, len, self.vm_memory_size);
            Err(OpenriscError::MemoryAccessError(address)) // Geçersiz bellek adresi hatası
        }
    }

     // VM belleğine belirli bir adrese byte yazma (örnek)
     pub fn write_memory_byte(&mut self, address: u32, value: u8) -> Result<(), OpenriscError> { // address u32
         let offset = address as usize;

         if self.vm_memory_ptr.is_null() {
              eprintln!("Hata: VM belleği ayrılmamış, yazma yapılamaz.");
              return Err(OpenriscError::ExecutionError("VM memory not allocated".to_string()));
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
             Err(OpenriscError::MemoryAccessError(address)) // Geçersiz bellek adresi hatası
         }
     }

     // VM belleğinden belirli bir adresten byte okuma (örnek)
     pub fn read_memory_byte(&self, address: u32) -> Result<u8, OpenriscError> { // address u32
         let offset = address as usize;

         if self.vm_memory_ptr.is_null() {
              eprintln!("Hata: VM belleği ayrılmamış, okuma yapılamaz.");
               return Err(OpenriscError::ExecutionError("VM memory not allocated".to_string()));
         }

         // Sınır kontrolü
         if offset < self.vm_memory_size {
             unsafe {
                 // Pointer aritmetiği ile doğru adrese git ve oku
                 Ok(*self.vm_memory_ptr.add(offset))
             }
         } else {
              eprintln!("Hata: Bellek sınırları dışında okuma girişimi: VM Adres = 0x{:x}, Boyut = {}", address, self.vm_memory_size);
              Err(OpenriscError::MemoryAccessError(address)) // Geçersiz bellek adresi hatası
         }
     }

    // Register okuma/yazma fonksiyonları
    pub fn get_register(&self, index: usize) -> Result<u32, OpenriscError> { // u32 registerlar
        if index < 32 {
            Ok(self.registers[index])
        } else {
            eprintln!("Hata: Geçersiz register indeksi: {}", index);
            Err(OpenriscError::ExecutionError(format!("Invalid register index: {}", index)))
        }
    }

    pub fn set_register(&mut self, index: usize, value: u32) -> Result<(), OpenriscError> { // u32 registerlar
        if index < 32 {
            self.registers[index] = value;
            Ok(())
        } else {
            eprintln!("Hata: Geçersiz register indeksi: {}", index);
            Err(OpenriscError::ExecutionError(format!("Invalid register index: {}", index)))
        }
    }
}
