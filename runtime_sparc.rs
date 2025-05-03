use crate::arch_sparc::SparcArchitecture;
use crate::arch_sparc::SparcArchitectureError; // SPARC mimarisine özgü hata türü

// Standard kütüphaneyi kullanmak için
use crate::standard_library::StandardLibrary;

// Sahne64 hata türünü içeri aktar (Sahne64 API'sından dönebilir)
use super::SahneError; // (varsa crate::SahneError olarak değiştirin)

// Diğer gerekli Rust core/alloc kütüphane elemanları
use alloc::string::String;
use alloc::format;
use alloc::vec::Vec; // Often needed indirectly

// std::result::Result zaten kapsamda olmalı, explicit import gerekli değil
// use std::result::Result; // Kaldırıldı


// Özel hata türü tanımlayın
#[derive(Debug)] // fmt::Display de burada derive edilebilir
pub enum SparcRuntimeError {
     /// Çalışma zamanı başlatılırken Sahne64 kaynaklı bir hata oluştu.
     InitializationError(SahneError),
    /// VM belleğine kod yüklenirken hata oluştu.
    CodeLoadError(String),
    /// SPARC mimarisi yürütülürken bir hata oluştu.
    ExecutionError(SparcArchitectureError), // String yerine SparcArchitectureError'ı kapsar
    /// VM'in yürütme döngüsü beklenmedik şekilde sonlandı (örn. exit komutu olmadan).
    UnexpectedTermination,
    /// VM başarılı bir şekilde yürütmeyi tamamladı (örn. exit komutu ile), çıkış kodu ile birlikte.
    ExecutionCompleted(i32), // Exit code
    // Orijinal koddaki String hatalar artık SparcArchitectureError içinde detaylandırılmalıdır.
    // Örneğin: Fetch/Decode hataları -> SparcArchitectureError::FetchError, DecodeError
    // Bellek hataları -> SparcArchitectureError::MemoryAccessError
    // Halt -> SparcArchitectureError::ExecutionError veya özel bir varyant
}

// SparcArchitectureError'dan SparcRuntimeError::ExecutionError'a dönüşüm
impl From<SparcArchitectureError> for SparcRuntimeError {
    fn from(err: SparcArchitectureError) -> Self {
        SparcRuntimeError::ExecutionError(err)
    }
}

// SahneError'dan SparcRuntimeError::InitializationError'a dönüşüm
// SparcArchitecture::new veya runtime::new içindeki diğer Sahne64 çağrıları için.
impl From<super::SahneError> for SparcRuntimeError { // use super::SahneError is assumed correct path
    fn from(err: super::SahneError) -> Self {
        SparcRuntimeError::InitializationError(err)
    }
}

impl std::error::Error for SparcRuntimeError {} // Implement Error trait

impl std::fmt::Display for SparcRuntimeError { // Implement Display trait
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         match self {
             SparcRuntimeError::InitializationError(e) => {
                 write!(f, "SPARC çalışma zamanı başlatma hatası: {:?}", e)
             }
             SparcRuntimeError::CodeLoadError(msg) => {
                 write!(f, "SPARC kod yükleme hatası: {}", msg)
             }
             SparcRuntimeError::ExecutionError(arch_error) => {
                 write!(f, "SPARC yürütme hatası: {}", arch_error) // SparcArchitectureError'ın Display implementasyonunu kullanır
             }
             SparcRuntimeError::UnexpectedTermination => {
                 write!(f, "SPARC yürütme beklenmedik şekilde sonlandı.")
             }
             SparcRuntimeError::ExecutionCompleted(code) => {
                 write!(f, "SPARC yürütme başarıyla tamamlandı. Çıkış kodu: {}", code)
             }
         }
     }
}


pub struct SparcRuntime {
    architecture: SparcArchitecture,
    standard_library: StandardLibrary, // Standart kütüphane örneği
}

// Drop implementasyonu artık SparcArchitecture tarafından yapılmalıdır.
// impl Drop for SparcRuntime { ... } // Kaldırıldı

impl SparcRuntime {
    /// Yeni bir SparcRuntime örneği oluşturur ve VM belleğini tahsis eder.
    ///
    /// # Arguments
    /// * `vm_memory_size` - VM için ayrılacak bellek boyutu.
    /// * `standard_library` - VM tarafından kullanılacak StandardLibrary instance'ı.
    ///
    /// Sahne64 bellek tahsisi veya SparcArchitecture başlatma başarısız olursa `SparcRuntimeError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, SparcRuntimeError> { // Return type changed
         println!("SPARC Runtime başlatılıyor...");

         // SparcArchitecture artık new fonksiyonunda bellek tahsisini yapıyor.
         // StandardLibrary'yi de SparcArchitecture'a geçirmeliyiz.
        let architecture = SparcArchitecture::new(vm_memory_size, standard_library.clone())?; // SparcArchitecture::new Result<Self, SahneError> döner, From implementasyonu kullanılır. StandardLibrary clone edilebilir olmalı.

         println!("SPARC Runtime başarıyla başlatıldı. Bellek boyutu: {} byte", architecture.vm_memory_size); // Boyutu architecture'dan al

        Ok(SparcRuntime {
             architecture,
             standard_library, // StandardLibrary'nin bir kopyası architecture'da, asıl instance burada tutulur.
        })
    }

    /// SPARC makine kodunu VM belleğine yükler ve yürütmeye başlar.
    ///
    /// # Arguments
    /// * `code` - Yürütülecek makine kodu baytları.
    ///
    /// VM yürütme durumu veya hatası döndürür (çıkış kodu veya hata).
    pub fn run(&mut self, code: &[u8]) -> Result<i32, SparcRuntimeError> { // Return type changed (i32 for exit code)
        println!("SPARC kodu VM belleğine yüklemeye başlanıyor...");

        // Yürütülecek kodu VM belleğine yükle.
        // SparcArchitecture içinde bellek erişim helperları olmalı (write_memory_slice).
        let code_size = code.len();
        if code_size > self.architecture.vm_memory_size {
             // Kodu yüklemek için VM belleği yeterli değil.
             eprintln!("Hata: Yüklenen kod VM belleğinden büyük (Kod boyutu: {}, Bellek boyutu: {})", code_size, self.architecture.vm_memory_size);
             return Err(SparcRuntimeError::CodeLoadError(format!("Code size ({}) exceeds VM memory size ({})", code_size, self.architecture.vm_memory_size)));
        }

        // Kodu VM belleğinin başlangıcına yaz.
        // write_memory_slice 0 adresine yazmaya çalışacaktır.
        match self.architecture.write_memory_slice(0, code) { // write_memory_slice should be in architecture
            Ok(_) => {
                println!("SPARC kodu VM belleğine başarıyla yüklendi ({} byte).", code_size);
                // Program sayacını kodun başlangıcına ayarla (genellikle 0).
                self.architecture.set_pc(0)?; // set_pc should be in architecture
            }
             Err(e) => {
                 // Belleğe yazma hatası (SparcArchitectureError)
                  eprintln!("Hata: Kodu VM belleğine yazarken hata oluştu: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                  return Err(e.into()); // SparcArchitectureError -> RuntimeError::ExecutionError
             }
        }


        println!("SPARC yürütme döngüsü başlatılıyor...");

        // VM yürütme döngüsü
        // execute_next_instruction PC'deki komutu yürütür, PC'yi ilerletir ve durumu günceller.
        // Başarı döner veya bir hata (illegal instruction, bellek hatası, syscall vb.) döner.
        // Exit syscall'u veya komutu özel olarak ele alınmalıdır (architecture tarafından sinyal verilir).

        loop {
            // Orijinaldeki manuel fetch-decode-execute döngüsü kaldırıldı.
            // Yerine SparcArchitecture::execute_next_instruction() çağrılacak.
            match self.architecture.execute_next_instruction() { // execute_next_instruction should be in architecture
                Ok(execution_status) => { // execution_status VM'in devam edip etmeyeceğini veya exit kodunu belirtebilir.
                    // Örnek: Eğer execute_next_instruction bir ExecutionStatus enum'ı dönüyorsa:
                     match execution_status {
                         ExecutionStatus::Continue => { /* Döngü devam etsin */ },
                         ExecutionStatus::Exit(exit_code) => {
                             println!("VM yürütme exit komutu ile sonlandı. Çıkış kodu: {}", exit_code);
                             return Ok(exit_code); // Başarılı çıkış
                         },
                         ExecutionStatus::Breakpoint => {
                              println!("VM breakpoint'e ulaştı.");
                    //          // Hata ayıklayıcıya kontrolü devret veya hata dön.
                              return Err(SparcRuntimeError::ExecutionError(SparcArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                         }
                     }
                     // Şimdilik, execute_next_instruction() sadece Result<()> dönüyor ve exit/breakpoint
                     // hatalarını SparcArchitectureError olarak döndürüyor varsayalım (ARM runtime örneğindeki gibi).
                     // Eğer Ok dönerse, döngü devam eder.

                    // Eğer SparcArchitecture::execute_next_instruction'dan Ok dönüyorsa ve bu bir exit sinyali değilse...
                    // Döngü devam eder.
                }
                // SparcArchitectureError içinden Exit veya Breakpoint gibi özel durumları yakala
                 Err(SparcArchitectureError::ExecutionError(msg)) if msg.starts_with("Exit with code:") => {
                    // execute_next_instruction exit durumunu özel bir ExecutionError mesajı ile bildiriyor varsayalım.
                    // Gerçek implementasyonda daha temiz bir Enum varyantı kullanılır.
                    let parts: Vec<&str> = msg.split(':').collect();
                    if parts.len() == 2 {
                        if let Ok(exit_code) = parts[1].trim().parse::<i32>() {
                            println!("VM yürütme exit komutu ile sonlandı. Çıkış kodu: {}", exit_code);
                            return Ok(exit_code); // Başarılı çıkış
                        }
                    }
                    // Mesaj formatı yanlışsa hata
                     eprintln!("Hata: Geçersiz exit mesajı formatı: {}", msg);
                     return Err(SparcRuntimeError::ExecutionError(SparcArchitectureError::ExecutionError(format!("Invalid exit message format: {}", msg))));
                }
                Err(SparcArchitectureError::ExecutionError(msg)) if msg == "Breakpoint reached" => {
                     println!("VM breakpoint'e ulaştı.");
                     // Breakpoint durumunda dur ve bir hata olarak bildir.
                     return Err(SparcRuntimeError::ExecutionError(SparcArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                }
                 Err(e) => {
                     // execute_next_instruction'dan dönen diğer hatalar (IllegalInstruction, MemoryAccessError, SystemCallError vb.)
                     eprintln!("SPARC yürütme hatası: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                     return Err(e.into()); // SparcArchitectureError -> RuntimeError::ExecutionError
                }
            }
        }

         // Eğer döngü hiçbir zaman sonlanmazsa (exit/hata olmadan), buraya unreachable! eklenebilir
         // veya bir timeout mekanizması olabilir.
          Ok(0) // Bu satıra normalde erişilmemeli
    }

    // Bellek okuma/yazma, register erişimi, fetch, decode artık SparcArchitecture içinde olmalıdır.
     fn fetch_instruction(&self) -> Result<Vec<u8>, String> { ... } // Kaldırıldı
     pub fn read_memory(&self, address: u64, size: usize) -> Vec<u8> { ... } // Kaldırıldı
     pub fn write_memory(&mut self, address: u64, data: &[u8]) { ... } // Kaldırıldı
     pub fn get_register(&self, register_index: usize) -> u64 { ... } // Kaldırıldı
     pub fn set_register(&mut self, register_index: usize, value: u64) { ... } // Kaldırıldı

     // StandardLibrary'yi kullanarak çıktı almak için fonksiyon.
     // Bu fonksiyon runtime tarafından tutulan StandardLibrary'yi kullanır.
     // VM kodu içinden çıktı, mimari içindeki syscall handler tarafından bu fonksiyonu çağırarak yapılır.
    pub fn print_string(&self, s: &str) {
         // StandardLibrary'nin print_string fonksiyonu Sahne64 resource::write kullanır.
        self.standard_library.print_string(s);
    }
}
