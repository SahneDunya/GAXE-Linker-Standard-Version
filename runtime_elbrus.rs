use crate::arch_elbrus::ElbrusArchitecture;
use crate::arch_elbrus::ElbrusArchitectureError; // Elbrus mimarisine özgü hata türü

// Sahne64 hata türünü içeri aktar (Sahne64 API'sından dönebilir)
use super::SahneError; // (varsa crate::SahneError olarak değiştirin)

// Standard kütüphaneyi kullanmak için
use crate::standard_library::StandardLibrary;

// Diğer gerekli Rust core/alloc kütüphane elemanları
use alloc::string::String;
use alloc::format;
use alloc::vec::Vec; // Often needed indirectly


// Özel hata türü tanımlayın
#[derive(Debug)] // fmt::Display de burada derive edilebilir
pub enum ElbrusRuntimeError {
    /// Çalışma zamanı başlatılırken Sahne64 kaynaklı bir hata oluştu.
    InitializationError(SahneError),
    /// VM belleğine kod yüklenirken hata oluştu.
    CodeLoadError(String),
    /// Elbrus mimarisi yürütülürken bir hata oluştu.
    ExecutionError(ElbrusArchitectureError), // String yerine ElbrusArchitectureError'ı kapsar
    /// VM'in yürütme döngüsü beklenmedik şekilde sonlandı (örn. exit komutu olmadan).
    UnexpectedTermination,
    /// VM başarılı bir şekilde yürütmeyi tamamladı (örn. exit komutu ile), çıkış kodu ile birlikte.
    ExecutionCompleted(i32), // Exit code
    // ElbrusRuntimeError'ın orijinal varyantları (ExecutionError(String), InvalidOpcode, MemoryError(String))
    // artık ElbrusArchitectureError içinde detaylandırılmalıdır.
    InvalidOpcode -> ElbrusArchitectureError::IllegalInstruction
    MemoryError(String) -> ElbrusArchitectureError::MemoryAccessError
    ExecutionError(String) -> ElbrusArchitectureError::ExecutionError (daha genel mimari hata)
    // Diğer Elbrus'a özgü hatalar ElbrusArchitectureError'a taşınmalıdır.
}

// ElbrusArchitectureError'dan ElbrusRuntimeError::ExecutionError'a dönüşüm
impl From<ElbrusArchitectureError> for ElbrusRuntimeError {
    fn from(err: ElbrusArchitectureError) -> Self {
        ElbrusRuntimeError::ExecutionError(err)
    }
}

// SahneError'dan ElbrusRuntimeError::InitializationError'a dönüşüm
// ElbrusArchitecture::new veya runtime::new içindeki diğer Sahne64 çağrıları için.
impl From<super::SahneError> for ElbrusRuntimeError { // use super::SahneError is assumed correct path
    fn from(err: super::SahneError) -> Self {
        ElbrusRuntimeError::InitializationError(err)
    }
}

impl std::error::Error for ElbrusRuntimeError {} // Implement Error trait

impl fmt::Display for ElbrusRuntimeError { // Implement Display trait
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         match self {
             ElbrusRuntimeError::InitializationError(e) => {
                 write!(f, "Elbrus çalışma zamanı başlatma hatası: {:?}", e)
             }
             ElbrusRuntimeError::CodeLoadError(msg) => {
                 write!(f, "Elbrus kod yükleme hatası: {}", msg)
             }
             ElbrusRuntimeError::ExecutionError(arch_error) => {
                 write!(f, "Elbrus yürütme hatası: {}", arch_error) // ElbrusArchitectureError'ın Display implementasyonunu kullanır
             }
             ElbrusRuntimeError::UnexpectedTermination => {
                 write!(f, "Elbrus yürütme beklenmedik şekilde sonlandı.")
             }
             ElbrusRuntimeError::ExecutionCompleted(code) => {
                 write!(f, "Elbrus yürütme başarıyla tamamlandı. Çıkış kodu: {}", code)
             }
         }
     }
}


pub struct ElbrusRuntime {
    architecture: ElbrusArchitecture,
    standard_library: StandardLibrary, // Standart kütüphane örneği
}

impl ElbrusRuntime {
    /// Yeni bir ElbrusRuntime örneği oluşturur ve VM belleğini tahsis eder.
    ///
    /// # Arguments
    /// * `vm_memory_size` - VM için ayrılacak bellek boyutu.
    /// * `standard_library` - VM tarafından kullanılacak StandardLibrary instance'ı.
    ///
    /// Sahne64 bellek tahsisi veya ElbrusArchitecture başlatma başarısız olursa `ElbrusRuntimeError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, ElbrusRuntimeError> { // Return type changed
         println!("Elbrus çalışma zamanı başlatılıyor...");

         // ElbrusArchitecture artık new fonksiyonunda bellek tahsisini yapıyor.
         // StandardLibrary'yi de ElbrusArchitecture'a geçirmeliyiz.
        let architecture = ElbrusArchitecture::new(vm_memory_size, standard_library.clone())?; // ElbrusArchitecture::new Result<Self, SahneError> döner, From implementasyonu kullanılır. StandardLibrary clone edilebilir olmalı.

         println!("Elbrus çalışma zamanı başarıyla başlatıldı.");

        Ok(ElbrusRuntime {
             architecture,
             standard_library, // StandardLibrary'nin bir kopyası architecture'da, asıl instance burada tutulur.
        })
    }

    /// Elbrus makine kodunu VM belleğine yükler ve yürütmeye başlar.
    ///
    /// # Arguments
    /// * `code` - Yürütülecek makine kodu baytları.
    ///
    /// VM yürütme durumu veya hatası döndürür (çıkış kodu veya hata).
    pub fn run(&mut self, code: &[u8]) -> Result<i32, ElbrusRuntimeError> { // Return type changed (i32 for exit code)
        println!("Elbrus kodunu VM belleğine yüklemeye başlanıyor...");

        // Yürütülecek kodu VM belleğine yükle.
        // ElbrusArchitecture içinde bellek erişim helperları olmalı (write_memory_slice).
        let code_size = code.len();
        if code_size > self.architecture.vm_memory_size {
             // Kodu yüklemek için VM belleği yeterli değil.
             eprintln!("Hata: Yüklenen kod VM belleğinden büyük (Kod boyutu: {}, Bellek boyutu: {})", code_size, self.architecture.vm_memory_size);
             return Err(ElbrusRuntimeError::CodeLoadError(format!("Code size ({}) exceeds VM memory size ({})", code_size, self.architecture.vm_memory_size)));
        }

        // Kodu VM belleğinin başlangıcına yaz.
        // write_memory_slice 0 adresine yazmaya çalışacaktır.
        match self.architecture.write_memory_slice(0, code) { // write_memory_slice should be in architecture
            Ok(_) => {
                println!("Elbrus kodu VM belleğine başarıyla yüklendi ({} byte).", code_size);
                // Program sayacını kodun başlangıcına ayarla (genellikle 0).
                self.architecture.set_pc(0)?; // set_pc should be in architecture
            }
             Err(e) => {
                 // Belleğe yazma hatası (ElbrusArchitectureError)
                  eprintln!("Hata: Kodu VM belleğine yazarken hata oluştu: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                  return Err(e.into()); // ElbrusArchitectureError -> RuntimeError::ExecutionError
             }
        }


        println!("Elbrus yürütme döngüsü başlatılıyor...");

        // VM yürütme döngüsü
        // execute_next_instruction PC'deki komutu yürütür, PC'yi ilerletir ve durumu günceller.
        // Başarı döner veya bir hata (illegal instruction, bellek hatası vb.) döner.
        // Exit syscall'u veya komutu özel olarak ele alınmalıdır (architecture tarafından sinyal verilir).

        loop {
            // ElbrusArchitecture::execute_instruction(code) çağrısı kaldırıldı.
            // Yerine ElbrusArchitecture::execute_next_instruction() çağrılacak.
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
                              // Hata ayıklayıcıya kontrolü devret veya hata dön.
                              return Err(ElbrusRuntimeError::ExecutionError(ElbrusArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                         }
                     }
                     // Şimdilik, execute_next_instruction() sadece Result<()> dönüyor ve exit/breakpoint
                     // hatalarını ElbrusArchitectureError olarak döndürüyor varsayalım (ARM runtime örneğindeki gibi).
                     // Eğer Ok dönerse, döngü devam eder.

                    // Eğer ElbrusArchitecture::execute_next_instruction'dan Ok dönüyorsa ve bu bir exit sinyali değilse...
                    // Döngü devam eder.
                }
                 Err(ElbrusArchitectureError::ExecutionError(msg)) if msg.starts_with("Exit with code:") => {
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
                     return Err(ElbrusRuntimeError::ExecutionError(ElbrusArchitectureError::ExecutionError(format!("Invalid exit message format: {}", msg))));
                }
                 Err(ElbrusArchitectureError::ExecutionError(msg)) if msg == "Breakpoint reached" => {
                      println!("VM breakpoint'e ulaştı.");
                      // Breakpoint durumunda dur ve bir hata olarak bildir.
                      return Err(ElbrusRuntimeError::ExecutionError(ElbrusArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                 }
                Err(e) => {
                     // execute_next_instruction'dan dönen diğer hatalar (IllegalInstruction, MemoryAccessError vb.)
                     eprintln!("Elbrus yürütme hatası: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                     return Err(e.into()); // ElbrusArchitectureError -> RuntimeError::ExecutionError
                }
            }
        }

        // Eğer döngü hiçbir zaman sonlanmazsa (exit/hata olmadan), buraya unreachable! eklenebilir
        // veya bir timeout mekanizması olabilir.
         Ok(0) // Bu satıra normalde erişilmemeli
    }

    // Elbrus programının sistem çağrılarını işlemesi için bir fonksiyon (taslak)
    // Bu fonksiyon artık runtime'da değil, ElbrusArchitecture içinde olmalıdır.
    // ElbrusArchitecture içindeki syscall işleyicisi StandardLibrary'yi kullanacaktır.
     pub fn handle_syscall(&mut self, syscall_number: u64, arg1: u64, arg2: u64, arg3: u64) -> Result<u64, ElbrusRuntimeError> { ... } // Kaldırıldı

    // Elbrus programının StandardLibrary'yi kullanarak çıktı alması için fonksiyon (architecture tarafından çağrılır)
    // Bu fonksiyon StandardLibrary'nin kendisinde olmalıdır. Runtime sadece StandardLibrary'yi tutar ve mimariye verir.
     pub fn print(&self, s: &str) { self.standard_library.print_string(s); } // Bu fonksiyon runtime'da değil, StandardLibrary'de veya mimarinin içindeki syscall handler'da olur.

    // Diğer Elbrus çalışma zamanı fonksiyonları...
    // Örneğin: get_register, set_register, read_memory, write_memory gibi (architecture'dan çağrılarak)
    // get_pc, set_pc vb.
    // ...
}
