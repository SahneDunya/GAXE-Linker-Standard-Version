use crate::memory as sahne_memory;
use crate::standard_library::StandardLibrary; // Standart kütüphaneye erişim için
use crate::SahneError; // Sahne64 hata türünü kullanmak için
use core::ptr; // İşaretçi operasyonları için
use alloc::vec::Vec; // Dinamik boyutlu string için Vec kullanabiliriz
use alloc::string::String; // String kullanabilmek için


pub struct ArmArchitecture {
    // VM'in bellek alanını doğrudan slice olarak tutmak yerine,
    // Sahne64 tarafından tahsis edilen alanın işaretçisini ve boyutunu tutalım.
    // Bu, Drop impl'inde belleği doğru şekilde serbest bırakmamızı sağlar.
    vm_memory_ptr: *mut u8,
    vm_memory_size: usize,

    standard_library: StandardLibrary, // Standart kütüphaneye erişim için

    // Gerçek bir VM için burada ARM registerları (r0-r15, sp, lr, pc, cpsr),
    // belki MMU durumu (page table base), diğer özel registerlar vs. tutulmalıdır.
    // Basitlik için şimdilik sadece belleği ele alıyoruz.
     registers: [u64; 16], // Örnek registerlar
     pc: u64, // Program Counter
}

// ArmArchitecture struct'ı scope dışına çıktığında veya drop edildiğinde
// Sahne64 tarafından tahsis edilen belleği serbest bırakmak için Drop trait'ini implemente edelim.
impl Drop for ArmArchitecture {
    fn drop(&mut self) {
        // Sahne64'ten allocate ile alınan belleği serbest bırak
        println!("VM belleği serbest bırakılıyor (Adres: {:p}, Boyut: {})...", self.vm_memory_ptr, self.vm_memory_size);
        match sahne_memory::release(self.vm_memory_ptr, self.vm_memory_size) {
            Ok(_) => println!("VM belleği başarıyla serbest bırakıldı."),
            Err(e) => eprintln!("VM belleğini serbest bırakma hatası: {:?}", e),
        }
    }
}


impl ArmArchitecture {
    // VM için bellek tahsisini Sahne64'ü kullanarak New fonksiyonunda yapalım.
    // Hata dönebileceği için Result kullanıyoruz.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, SahneError> {
        // Sahne64 memory modülünü kullanarak VM için bellek alanı tahsis et
        println!("Sahne64 kullanarak {} byte VM belleği tahsis ediliyor...", vm_memory_size);
        let vm_memory_ptr = sahne_memory::allocate(vm_memory_size)?; // sahne_memory::allocate çağrısı

        println!("VM belleği tahsis edildi: {:p}", vm_memory_ptr);

        Ok(ArmArchitecture {
            vm_memory_ptr,
            vm_memory_size,
            standard_library,
             registers: [0; 16], // Registerları sıfırla
             pc: 0, // Program Counter'ı sıfırla (veya giriş noktasına ayarla)
        })
    }

    // Tahsis edilen bellek alanına güvenli erişim için yardımcı fonksiyon
    fn get_memory_slice(&mut self) -> &mut [u8] {
        // `unsafe` blok kullanımı işaretçi manipülasyonu içerdiği için gereklidir.
        // Tahsis edilen alanın geçerli ve boyutunun doğru olduğundan emin olmak çağıranın sorumluluğundadır.
        unsafe { core::slice::from_raw_parts_mut(self.vm_memory_ptr, self.vm_memory_size) }
    }


    pub fn execute_instruction(&mut self, instruction: &[u8]) {
        // ARM komutunu yürütme mantığı... (Gerçek bir VM'de PC artışı burada olurdu)

        if instruction.is_empty() {
            println!("Geçersiz boş komut!");
            // Hata işleme
            return;
        }

        // Komut yürütülürken VM belleğine erişmek için slice'ı alalım
        let vm_memory = self.get_memory_slice();

        // Komutun opcode'una göre işlemi yönlendir
        match instruction[0] {
            0x00..=0x0F => { // Örnek: "NOP" komutları
                self.execute_nop(instruction);
            }
            0x10..=0x2F => { // Örnek: "MOV" (register'dan register'a taşıma)
                 self.execute_mov_reg_to_reg(instruction);
            }
            0x30..=0x4F => { // Örnek: "LDR" (bellekten yükleme)
                self.execute_ldr(vm_memory, instruction); // vm_memory slice'ını pass et
            }
            0x50..=0x6F => { // Örnek: "STR" (belleğe kaydetme)
                self.execute_str(vm_memory, instruction); // vm_memory slice'ını pass et
            }
            // Örnek: "PRINT" (standart çıktıya yazdırma)
            0x70..=0x7F => {
                self.execute_print(vm_memory, instruction); // vm_memory slice'ını pass et
            }
            // ... Diğer ARM komutları ...
            _ => {
                println!("Bilinmeyen ARM komutu: {:?}", instruction);
                // Bilinmeyen komut hatasını işle...
            }
        }
        // Gerçek bir VM'de PC'yi sonraki komuta ilerletme burada olurdu.
         self.pc += instruction_size;
    }

    // execute_nop ve execute_mov_reg_to_reg VM belleğine doğrudan erişmediği için imzaları değişmedi.
    fn execute_nop(&self, instruction: &[u8]) {
        println!("NOP komutu yürütülüyor: {:?}", instruction);
    }

    fn execute_mov_reg_to_reg(&self, instruction: &[u8]) {
        println!("MOV (register'dan register'a) komutu yürütülüyor: {:?}", instruction);
        // Register işlemleri burada yapılır. self.registers kullanılabilir.
    }

    // Bellek erişimi yapan fonksiyonlar vm_memory slice'ını parametre olarak alsın
    fn execute_ldr(&self, vm_memory: &mut [u8], instruction: &[u8]) {
        println!("LDR (bellekten yükleme) komutu yürütülüyor: {:?}", instruction);
        // LDR komutu, VM adres alanı içindeki bir adresten okuma yapar.
        // Bu adres, Sahne64 tarafından tahsis edilen 'vm_memory_ptr' ile başlayan blok içindedir.
        // Doğrudan Sahne64 allocate/release çağrısı yapılmaz.

        // ... VM registerlarından ve/veya sabitlerden bellek adresini hesaplama mantığı ...
        // Örnek: Eğer komutun 2. baytı 0x00-0xFF arası bir adres offseti ise
        if instruction.len() > 1 {
            let offset = instruction[1] as usize; // VM adres alanı içindeki offset
            // Güvenli bir şekilde vm_memory slice'ı içinden okuma yap
            if offset < vm_memory.len() {
                let value = vm_memory[offset];
                println!("  - Bellekten okunan değer (VM Adresi 0x{:X}): 0x{:X}", offset, value);
                // ... Okunan veriyi hedef VM registera yazma (örn: self.registers[dest_reg] = value as u64;) ...
            } else {
                println!("  - Hata: Geçersiz VM bellek adresi: 0x{:X}", offset);
                // Geçersiz bellek erişimi durumunda VM task'ını sonlandırabilir veya hata işleyebilirsiniz.
            }
        } else {
            println!("  - Hata: LDR komutu eksik operand.");
            // Geçersiz komut formatı hatası
        }
    }

    fn execute_str(&mut self, vm_memory: &mut [u8], instruction: &[u8]) {
        println!("STR (belleğe kaydetme) komutu yürütülüyor: {:?}", instruction);
        // STR komutu, VM adres alanı içindeki bir adrese yazma yapar.
        // Bu adres, Sahne64 tarafından tahsis edilen 'vm_memory_ptr' ile başlayan blok içindedir.
        // Doğrudan Sahne64 allocate/release çağrısı yapılmaz.

        // ... VM registerlarından ve/veya sabitlerden bellek adresini ve yazılacak değeri hesaplama mantığı ...
        // Örnek: Eğer komutun 2. baytı adres offseti ve 3. baytı yazılacak değer ise
        if instruction.len() > 2 {
            let offset = instruction[1] as usize; // VM adres alanı içindeki offset
            let value = instruction[2]; // Yazılacak değer (örn: bir VM registerından alınmış)

            // Güvenli bir şekilde vm_memory slice'ı içine yazma yap
            if offset < vm_memory.len() {
                vm_memory[offset] = value;
                println!("  - Belleğe yazılan değer 0x{:X} (VM Adresi 0x{:X})", value, offset);
            } else {
                println!("  - Hata: Geçersiz VM bellek adresi: 0x{:X}", offset);
                 // Geçersiz bellek erişimi durumunda VM task'ını sonlandırabilir veya hata işleyebilirsiniz.
            }
        } else {
            println!("  - Hata: STR komutu eksik operand.");
            // Geçersiz komut formatı hatası
        }
    }

    // PRINT komutu örneği güncellendi
    fn execute_print(&self, vm_memory: &mut [u8], instruction: &[u8]) {
        println!("PRINT komutu yürütülüyor: {:?}", instruction);
        // STANDART KÜTÜPHANE VE SAHNE64 ENTEGRASYONU
        // PRINT komutu argüman olarak bir stringin bellekteki adresini alıyor varsayalım.
        // Bu adres, VM'in adres alanındadır, yani vm_memory slice'ı içindedir.
        // Komutun formatına göre bu adres ve stringin uzunluğu çözümlenmelidir.
        // Basitlik için, sabit bir adresten null-terminated bir string okuyalım.
        // Gerçekte, komutun operandlarından adres ve uzunluk/null terminator bilgisi alınır.
        let start_address = 0x10; // Örnek başlangıç adresi (VM adres alanı içinde)

        if start_address < vm_memory.len() {
            let mut current_address = start_address;
            let mut printed_string_bytes: Vec<u8> = Vec::new(); // Dinamik boyut için Vec

            // Null terminator (0) görene kadar VM belleğinden oku
            while current_address < vm_memory.len() {
                let byte = vm_memory[current_address];
                if byte == 0 { // Null-terminated string
                    break;
                }
                printed_string_bytes.push(byte);
                current_address += 1;
            }

            // Okunan byte'ları string'e çevirip standart kütüphaneye pass et
            match core::str::from_utf8(&printed_string_bytes) {
                Ok(s) => {
                    self.standard_library.print_string(s); // StandardLibrary aracılığıyla çıktı
                },
                Err(_) => {
                    // Geçersiz UTF-8 durumunu ele al, örneğin ham byte'ları yazdır
                    eprintln!("PRINT komutu: Bellekte geçersiz UTF-8 string (VM Adresi 0x{:X}).", start_address);
                    // İsteğe bağlı: standard_library'de ham byte yazdırma fonksiyonu varsa onu kullan
                }
            }
        } else {
            eprintln!("PRINT komutu: Geçersiz başlangıç adresi (VM Adresi 0x{:X}).", start_address);
            // Geçersiz adres hatasını işle
        }
    }


    // Diğer ARM mimarisine özgü fonksiyonlar ve komut yürütme mantıkları...
    // Örneğin, VM içinde bir sistem çağrısı (syscall) komutu yürütüldüğünde,
    // buradaki bir fonksiyon bu çağrıyı yakalar ve Sahne64 API'sını kullanarak
    // ilgili işlemi (dosya açma, network mesajı gönderme vb.) gerçekleştirir.
     fn execute_vm_syscall(&mut self, syscall_number: u64, args: &[u64]) {
         match syscall_number {
    //         // VM içinden gelen bellek tahsis syscall'u
             VM_SYSCALL_ALLOCATE => {
                  let size = args[0] as usize;
                  match sahne_memory::allocate(size) {
                       Ok(ptr) => { /* ptr'ı VM adres alanına eşle ve VM register'ına dön */ },
                       Err(e) => { /* VM'e hata kodu dön */ },
                  }
             }
             // Diğer VM syscall'ları...
             _ => { /* Bilinmeyen VM syscall'u */ }
         }
     }
}

// Örnek kullanım (std feature etkinse main içinde veya no_std ortamında uygun entry point'te)
// Bu kısım `ArmArchitecture`'ın nasıl oluşturulup kullanılacağını gösterir.
// ```rust
 #[cfg(feature = "std")]
 fn example_vm_usage() -> Result<(), SahneError> {
//      // StandardLibrary'nin bir örneği (gerçek implementasyonu Sahne64 API'sını kullanır)
      let std_lib = StandardLibrary::new(/* ... gerekli argümanlar ... */);
//
//      // VM belleği için boyut belirle
      let vm_mem_size = 1024 * 1024; // 1MB
//
//      // Sahne64 kullanarak VM için bellek tahsis ederek ArmArchitecture instance'ını oluştur
      let mut arm_vm = ArmArchitecture::new(vm_mem_size, std_lib)?;
//
      println!("VM instance oluşturuldu ve belleği tahsis edildi.");
//
//      // Örnek VM komutları (bu byte dizisi, .gaxe dosyasının içeriğini temsil eder)
//      // Gerçekte bu komutlar .gaxe dosyasından okunur ve PC takip edilerek tek tek yürütülür.
      let vm_code = [
//          // VM belleğinin 0x10 adresine "Merhaba Sahne64!\0" stringini yaz (Örnek data)
//          // Gerçek ARM'de STR komutları serisi veya data section olurdu
          0x4d, // Örnek opcode: STR (değer 0x4d)
          0x10, // Örnek operand: Hedef adres offset 0x10
          b'M', // Örnek operand: Yazılacak değer 'M'
//
          0x4d, 0x11, b'e',
          0x4d, 0x12, b'r',
          0x4d, 0x13, b'h',
          0x4d, 0x14, b'a',
          0x4d, 0x15, b'b',
          0x4d, 0x16, b'a',
          0x4d, 0x17, b' ',
          0x4d, 0x18, b'S',
          0x4d, 0x19, b'a',
          0x4d, 0x1a, b'h',
          0x4d, 0x1b, b'n',
          0x4d, 0x1c, b'e',
          0x4d, 0x1d, b'6',
          0x4d, 0x1e, b'4',
          0x4d, 0x1f, b'!',
          0x4d, 0x20, b'\0', // Null terminator
//
//          // PRINT komutu (VM adres 0x10'daki stringi yazdır)
          0x70, // Örnek opcode: PRINT
          0x10, // Örnek operand: Stringin başlangıç VM adresi (bu örneğe göre)
//
//          // NOP komutu
          0x00,
//
//          // VM'i sonlandırma komutu (Örnek)
           0xFF, // Örnek: EXIT opcode
      ];
//
//      // Komutları yürüt (gerçekte bir döngü ve PC takibi ile olur)
//      // Bu örnekte her komutu tek tek yürütüyormuş gibi simüle edelim.
      let mut instruction_ptr = 0;
      while instruction_ptr < vm_code.len() {
//           // Basit bir sabit komut uzunluğu varsayalım (örn: 3 byte)
           let instruction_len = match vm_code[instruction_ptr] {
                0x00..=0x0F => 1, // NOP 1 byte
                0x10..=0x2F => 3, // MOV 3 byte (opcode, src_reg, dest_reg) - Örneğe uymuyor ama konsept
                0x30..=0x4F => 2, // LDR 2 byte (opcode, offset) - Örneğe uymuyor
                0x50..=0x6F => 3, // STR 3 byte (opcode, offset, value) - Örneğe uyuyor
                0x70..=0x7F => 2, // PRINT 2 byte (opcode, addr_offset) - Örneğe uyuyor
                _ => {
                     eprintln!("Bilinmeyen komut opcode'u 0x{:X} adres 0x{:X}!", vm_code[instruction_ptr], instruction_ptr);
//                     // Hata durumunda döngüyü kır veya task'ı sonlandır
                     break;
                }
           };
//
           if instruction_ptr + instruction_len > vm_code.len() {
                eprintln!("Komut byte'ları yetersiz, adres 0x{:X}!", instruction_ptr);
                break;
           }
//
           let current_instruction = &vm_code[instruction_ptr .. instruction_ptr + instruction_len];
           arm_vm.execute_instruction(current_instruction);
//
//           // PC'yi bir sonraki komuta ilerlet
           instruction_ptr += instruction_len;
//
           // Gerçekte burada VM task'ı yield yapabilir veya uyuyabilir.
            task::yield_now()?;
      }
//
      println!("VM komut yürütme bitti.");
//
//      // arm_vm instance'ı buradan çıktığında veya düşürüldüğünde belleği otomatik serbest kalır (Drop trait sayesinde)
      Ok(())
 }
