use crate::gaxe_format::Architecture; // Gaxe format mimari enum'ı (eğer StandardLibrary kullanıyorsa)
// Sahne64 modüllerini içeri aktar (kendi crate'inizdeki yola göre ayarlayın)
use crate::memory as sahne_memory; // Bellek yönetimi için Sahne64 modülü
use crate::resource; // Kaynak yönetimi için Sahne64 modülü (StandardLibrary kullanacak)
use crate::arch; // Mimariye özel Sahne64 syscall numaraları (StandardLibrary kullanacak)
use crate::SahneError; // Sahne64 hata türü

use crate::standard_library::StandardLibrary; // Standard kütüphaneyi içeri aktar

use core::ptr; // İşaretçi operasyonları için
use alloc::vec::Vec; // Dinamik vektör için (Okunan stringi geçici tutmak için gerekebilir)
use alloc::string::String; // String için (Okunan stringi geçici tutmak için gerekebilir)


pub struct X86Architecture {
    // x86 mimarisinin iç durumunu tutacak alanlar
    registers: X86Registers,
    // Sahne64 tarafından yönetilen VM belleği için pointer ve boyutu
    vm_memory_ptr: *mut u8,
    vm_memory_size: usize,
    // Standard kütüphane instance'ı (VM içindeki guest code tarafından syscall'lar aracılığıyla kullanılır)
    standard_library: StandardLibrary,
}

// X86 registerlarını temsil eden struct (Değişiklik yok)
#[derive(Debug)]
struct X86Registers {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    eip: u32,
    esp: u32, // Stack Pointer
    ebp: u32, // Base Pointer
    esi: u32, // Source Index
    edi: u32, // Destination Index
    // ... diğer registerlar (segment registerları, flags vb.) ...
    eflags: u32, // Flags register
}

// Belleği serbest bırakmak için Drop trait'ini implemente et
impl Drop for X86Architecture {
    fn drop(&mut self) {
         // Eğer belleğe bir işaretçi varsa ve null değilse serbest bırak
         if !self.vm_memory_ptr.is_null() {
             println!("x86 VM belleği serbest bırakılıyor (Adres: {:p}, Boyut: {})...", self.vm_memory_ptr, self.vm_memory_size);
              // Sahne64 memory::release fonksiyonunu kullanın
              match sahne_memory::release(self.vm_memory_ptr, self.vm_memory_size) {
                  Ok(_) => println!("x86 VM belleği başarıyla serbest bırakıldı."),
                  Err(e) => eprintln!("x86 VM belleğini serbest bırakma hatası: {:?}", e),
              }
         }
    }
}


impl X86Architecture {
    /// Yeni bir `X86Architecture` örneği oluşturur ve VM belleğini Sahne64 kullanarak tahsis eder.
    /// Bellek tahsisi başarısız olursa `SahneError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, SahneError> {
         println!("Sahne64 kullanarak {} byte x86 VM belleği tahsis ediliyor...", vm_memory_size);
        // Sahne64 memory modülünü kullanarak VM için bellek alanı tahsis et
        let vm_memory_ptr = sahne_memory::allocate(vm_memory_size)?; // sahne_memory::allocate çağrısı, hata Result ile propagate edilir.

         println!("x86 VM belleği tahsis edildi: {:p}", vm_memory_ptr);


        Ok(X86Architecture {
            registers: X86Registers::new(),
            vm_memory_ptr,
            vm_memory_size,
            standard_library, // StandardLibrary örneğini al
        })
    }

     // Tahsis edilen bellek alanına güvenli erişim için yardımcı fonksiyon
     // VM belleği slice'ını döndürür. İşaretçi null ise panikleyebilir.
     fn get_memory_slice(&mut self) -> &mut [u8] {
         if self.vm_memory_ptr.is_null() {
              // Bellek tahsis hatası sonrası veya Drop sonrası çağrılırsa bu panikleyebilir.
              // Daha sağlam bir VM runner'da bu durumda Result dönebilir veya
              // VM task'ı hata state'ine alınabilir.
              panic!("Attempted to get memory slice from null VM pointer");
         }
         unsafe { core::slice::from_raw_parts_mut(self.vm_memory_ptr, self.vm_memory_size) }
     }


    // execute_instruction fonksiyonu VM kodunu byte dizisi olarak alır
    // ve EIP (Program Counter) register'ını içeride tutar.
    pub fn execute_instruction(&mut self, code: &[u8]) {
        // EIP registerı, yürütülecek komutun VM bellek adresi olarak kullanılır.
         let eip = self.registers.eip;

        if eip as usize >= self.vm_memory_size {
             // VM belleği sınırlarının dışına çıktı (kod da VM belleğinde olmalı)
             eprintln!("Hata: VM belleği sınırının dışına çıkıldı (EIP: 0x{:x}, Bellek Boyutu: {})", eip, self.vm_memory_size);
             // VM task'ını sonlandır veya hata işle.
             return;
         }

         // VM belleğindeki kod slice'ına eriş
         let vm_memory = self.get_memory_slice();
         let vm_code_slice = &vm_memory[eip as usize ..]; // EIP'den sonrasını kod olarak kabul et


        if vm_code_slice.is_empty() {
             eprintln!("Hata: Yürütülecek komut kalmadı (EIP: 0x{:x})", eip);
             // VM yürütmeyi durdur.
             return;
         }

        let opcode = vm_code_slice[0];
        println!("Yürütülen opcode: 0x{:x} (EIP: 0x{:x})", opcode, eip);

        // Komutun uzunluğunu belirle ve PC'yi buna göre ilerlet
        // Bu çok basitleştirilmiş bir decode/execute döngüsüdür.
        // Gerçek x86 emülatörleri komut uzunluğunu doğru çözmelidir.
        let mut instruction_len: u32 = 1; // Varsayılan minimum uzunluk

        match opcode {
            0xB8..=0xBF => { // MOV r32, imm32 (B8=EAX, B9=ECX, BA=EDX, BB=EBX, BC=ESP, BD=EBP, BE=ESI, BF=EDI)
                 // Komut formatı: [opcode, imm32_byte1, ..., imm32_byte4] (5 byte)
                 instruction_len = 5;
                 if vm_code_slice.len() >= instruction_len as usize {
                      let dest_register_index = (opcode - 0xB8) as usize;
                      let immediate = u32::from_le_bytes([
                          vm_code_slice[1], vm_code_slice[2], vm_code_slice[3], vm_code_slice[4],
                      ]);
                      // Registerı güncelle
                      match dest_register_index {
                          0 => self.registers.eax = immediate,
                          1 => self.registers.ecx = immediate,
                          2 => self.registers.edx = immediate,
                          3 => self.registers.ebx = immediate,
                          4 => self.registers.esp = immediate,
                          5 => self.registers.ebp = immediate,
                          6 => self.registers.esi = immediate,
                          7 => self.registers.edi = immediate,
                          _ => unreachable!("Invalid register index for MOV r32, imm32"), // Koda göre buraya düşmemeli
                      }
                      println!("  MOV {:?}, 0x{:x} komutu yürütüldü.", dest_register_index, immediate); // Kayıt ismini yazdırabiliriz
                 } else {
                     eprintln!("  Hata: Yetersiz komut byte'ı (MOV r32, imm32)");
                     // VM yürütme hatası işleme
                      instruction_len = vm_code_slice.len() as u32; // Kalan byte'ları tüket
                 }
             }
            // **BELLEK OKUMA ÖRNEĞİ**
            0x8B => { // MOV r32, r/m32 (Basitleştirilmiş halini ele alalım: MOV reg, [disp8])
                 // Komut formatı: [opcode, ModR/M, disp8] (3 byte)
                 instruction_len = 3;
                 if vm_code_slice.len() >= instruction_len as usize {
                      let modrm = vm_code_slice[1];
                      let dest_register_index = ((modrm >> 3) & 0x7) as usize; // reg alanı
                      // ModR/M byte'ının Mod alanına göre adresleme tipi belirlenir.
                      // Basitçe Mod = 00 (register indirect + displacement) ve R/M = 5 (disp32) veya SIB+disp8/32 alalım
                      // Burada sadece [disp8] formatını simüle ediyoruz, R/M = 4 (SIB)
                      let displacement = vm_code_slice[2] as u32; // disp8 (işaretli olabilir gerçekte)

                      // Bellekten değeri oku (şu an sadece 1 byte okuyor gibi görünüyor örnek, 4 byte okumalı)
                       // VM belleği slice'ı üzerinden okuma yap
                      let address = displacement as usize; // VM adres alanı içindeki adres (displacement 0 olunca doğrudan disp oluyor)
                      let value;
                      if address + 4 <= vm_memory.len() { // 32-bit (kelime) okuma için sınır kontrolü
                          // Little-endian olarak 4 byte oku (x86 little-endian)
                          let value_bytes: [u8; 4] = vm_memory[address..address+4].try_into().unwrap(); // Sınır kontrolü yapıldı
                          value = u32::from_le_bytes(value_bytes);
                          println!("  Bellekten okunan değer (VM Adresi 0x{:x}): 0x{:x}", address, value);

                          // Hedef registera yaz
                          match dest_register_index {
                              0 => self.registers.eax = value,
                              1 => self.registers.ecx = value,
                              2 => self.registers.edx = value,
                              3 => self.registers.ebx = value,
                              4 => self.registers.esp = value,
                              5 => self.registers.ebp = value,
                              6 => self.registers.esi = value,
                              7 => self.registers.edi = value,
                              _ => eprintln!("  Hata: Desteklenmeyen hedef register (0x8B): {}", dest_register_index),
                          }
                           println!("  MOV {:?}, [0x{:x}] komutu yürütüldü.", dest_register_index, address);

                      } else {
                          eprintln!("  Hata: Geçersiz bellek adresi (MOV r32, [disp8]): 0x{:x}", address);
                          // VM yürütme hatası işleme
                      }
                 } else {
                     eprintln!("  Hata: Yetersiz komut byte'ı (MOV r32, [disp8])");
                      // VM yürütme hatası işleme
                      instruction_len = vm_code_slice.len() as u32; // Kalan byte'ları tüket
                 }
            }
            // **SİSTEM ÇAĞRISI ÖRNEĞİ (ÇOK BASİT)**
            // INT 0x80 (Linux syscall convention) veya SYSCALL (daha modern)
            // Burada INT 0x80'i ele alalım
            0xCD => { // INT (Interrupt) Opcode'u
                instruction_len = 2; // INT opcode (1 byte) + Interrupt Vector (1 byte)
                if vm_code_slice.len() >= instruction_len as usize {
                     let interrupt_vector = vm_code_slice[1];
                     if interrupt_vector == 0x80 { // Linux Syscall Vector
                         println!("  Sistem çağrısı (INT 0x80) algılandı");
                         // Syscall numarası ve argümanlar registerlarda bulunur.
                         // Linux x86 32-bit Fastcall/Syscall Convention:
                         // Syscall numarası: EAX
                         // Argümanlar: EBX, ECX, EDX, ESI, EDI, EBP (veya Stack)
                         let syscall_number = self.registers.eax;
                         // Örnek: Sadece print_string syscall'unu işleyelim
                         // Syscall 4 (write) veya custom syscall 1 gibi
                         println!("  Syscall Numarası: {}", syscall_number);

                         // Syscall'ı işleyen bir fonksiyon çağır.
                         // Bu fonksiyon StandardLibrary'yi veya doğrudan Sahne64 API'sını kullanır.
                         // self.handle_vm_syscall(syscall_number as u64, self.registers); // Registerları pass et
                         // Dönüş değeri ve hata registerlara (EAX, EDX, EFLAGS) yazılır.

                         // Basit çıktı örneği için handle_syscall_example gibi bir şey kullanalım
                         // Varsayım: syscall_number 1 ise, EBX'te adres, ECX'te uzunluk var.
                         if syscall_number == 1 { // Örnek print_string syscall'u
                              let address = self.registers.ebx as usize; // VM bellek adresi
                              let length = self.registers.ecx as usize; // Uzunluk

                              if address + length <= vm_memory.len() { // Sınır kontrolü
                                   let string_slice = &vm_memory[address .. address + length];
                                   // Stringi StandardLibrary'ye pass et
                                   match core::str::from_utf8(string_slice) {
                                       Ok(s) => {
                                           self.standard_library.print_string(s);
                                           // Başarı durumunu kayıtlara yaz (örn: EAX = uzunluk)
                                           self.registers.eax = length as u32;
                                       },
                                       Err(_) => {
                                           eprintln!("  Hata: VM belleğinde geçersiz UTF-8 stringi (VM Adresi 0x{:x}, Uzunluk: {})", address, length);
                                            // Hata durumunu kayıtlara yaz (örn: EAX = -EFAULT)
                                           self.registers.eax = (-14i32) as u32; // Örnek hata kodu (EFAULT benzeri)
                                           // EFLAGS'daki carry flag'i set edilebilir
                                       }
                                   }
                              } else {
                                   eprintln!("  Hata: SYSCALL çıktı stringi bellek sınırları dışında (VM Adres: 0x{:x}, Uzunluk: {}, Bellek Boyutu: {})", address, length, self.vm_memory_size);
                                    // Hata durumunu kayıtlara yaz
                                   self.registers.eax = (-14i32) as u32; // Örnek hata kodu
                              }
                         } else {
                             eprintln!("  Hata: Bilinmeyen x86 VM syscall: {}", syscall_number);
                             // Bilinmeyen syscall hatasını kayıtlara yaz
                             self.registers.eax = (-38i32) as u32; // Örnek hata kodu (ENOSYS benzeri)
                         }


                     } else {
                         eprintln!("  Hata: Desteklenmeyen interrupt vektörü: 0x{:x}", interrupt_vector);
                          // VM yürütme hatası işleme
                     }
                } else {
                     eprintln!("  Hata: Yetersiz komut byte'ı (INT)");
                      // VM yürütme hatası işleme
                      instruction_len = vm_code_slice.len() as u32; // Kalan byte'ları tüket
                }
            }
            // ... diğer opcode'lar ...
            _ => {
                eprintln!("Bilinmeyen x86 opcode 0x{:x} yürütülüyor (EIP: 0x{:x})", opcode, eip);
                 // VM yürütme hatası işleme
                 // instruction_len = 1; // Varsayılan olarak 1 byte ilerle
            }
        }

        // PC'yi ilerlet
         self.registers.eip += instruction_len;
    }

    // Diğer x86 mimarisine özgü fonksiyonlar...

    pub fn get_eax_register(&self) -> u32 {
        self.registers.eax
    }

    pub fn get_eip_register(&self) -> u32 {
        self.registers.eip
    }

    // VM belleğine veri yazmak için fonksiyon
    // Adres ve veri (byte slice) alır
    pub fn write_memory(&mut self, address: u32, data: &[u8]) {
        let offset = address as usize;
        let data_len = data.len();

        // Bellek pointerı geçerli mi kontrol et
        if self.vm_memory_ptr.is_null() {
             eprintln!("Hata: VM belleği ayrılmamış, yazma yapılamaz.");
             // VM'e hata bildir
             return;
        }

        // Sınır kontrolü
        if offset < self.vm_memory_size && offset + data_len <= self.vm_memory_size {
            // VM belleği slice'ı al ve veriyi kopyala
             let vm_memory = self.get_memory_slice(); // Mutable slice alır
             vm_memory[offset .. offset + data_len].copy_from_slice(data);
              println!("  Belleğe yazıldı: VM Adres = 0x{:x}, Boyut = {}", address, data_len);
        } else {
             eprintln!("Hata: Bellek sınırları dışında yazma girişimi: VM Adres = 0x{:x}, Boyut = {}, Bellek Boyutu = {}", address, data_len, self.vm_memory_size);
            // VM'e hata bildir
        }
    }

     // VM belleğinden veri okumak için fonksiyon (örn: instruction fetch, data load)
     // Adres ve okunacak boyut alır, Okunan byte'ları döner (Vec<u8>) veya Hata döner.
     // Basitlik için byte slice olarak dönelim (daha verimli olabilir)
     pub fn read_memory_slice(&self, address: u32, len: usize) -> Result<&[u8], &'static str> {
         let offset = address as usize;

         if self.vm_memory_ptr.is_null() {
             eprintln!("Hata: VM belleği ayrılmamış, okuma yapılamaz.");
             return Err("VM belleği ayrılmamış");
         }

         // Sınır kontrolü
         if offset < self.vm_memory_size && offset + len <= self.vm_memory_size {
              // Read-only slice al
             let vm_memory = unsafe { core::slice::from_raw_parts(self.vm_memory_ptr, self.vm_memory_size) };
             Ok(&vm_memory[offset .. offset + len])
         } else {
              eprintln!("Hata: Bellek sınırları dışında okuma girişimi: VM Adres = 0x{:x}, Boyut = {}, Bellek Boyutu = {}", address, len, self.vm_memory_size);
             Err("Bellek sınırları dışında okuma")
         }
     }

    // Diğer x86 mimarisine özgü fonksiyonlar...
    // handle_vm_syscall(self, syscall_num, registers) -> Result<(), VmError> gibi
}

impl X86Registers {
    // X86 registerları için başlangıç değerleri
    pub fn new() -> Self {
        X86Registers {
            eax: 0, ebx: 0, ecx: 0, edx: 0,
            eip: 0, // Genellikle kodun başlangıç adresi
            esp: 0, // Stack pointer (genellikle belleğin sonuna ayarlanır)
            ebp: 0, esi: 0, edi: 0,
            eflags: 0x00000002, // Başlangıç bayrakları (Rezerve bayrak 1)
            // ... diğer registerlar ...
        }
    }
}
