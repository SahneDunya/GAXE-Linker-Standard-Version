use crate::arch_powerpc::PowerpcArchitecture;
use crate::arch_powerpc::PowerpcArchitectureError; // PowerPC mimarisine özgü hata türü

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
pub enum PowerpcRuntimeError {
     /// Çalışma zamanı başlatılırken Sahne64 kaynaklı bir hata oluştu.
     InitializationError(SahneError),
    /// VM belleğine kod yüklenirken hata oluştu.
    CodeLoadError(String),
    /// PowerPC mimarisi yürütülürken bir hata oluştu.
    ExecutionError(PowerpcArchitectureError), // String yerine PowerpcArchitectureError'ı kapsar
    /// VM'in yürütme döngüsü beklenmedik şekilde sonlandı (örn. exit komutu olmadan).
    UnexpectedTermination,
    /// VM başarılı bir şekilde yürütmeyi tamamladı (örn. exit komutu ile), çıkış kodu ile birlikte.
    ExecutionCompleted(i32), // Exit code
    // Diğer çalışma zamanı hata varyantları eklenebilir.
}

// PowerpcArchitectureError'dan PowerpcRuntimeError::ExecutionError'a dönüşüm
impl From<PowerpcArchitectureError> for PowerpcRuntimeError {
    fn from(err: PowerpcArchitectureError) -> Self {
        PowerpcRuntimeError::ExecutionError(err)
    }
}

// SahneError'dan PowerpcRuntimeError::InitializationError'a dönüşüm
// PowerpcArchitecture::new veya runtime::new içindeki diğer Sahne64 çağrıları için.
impl From<super::SahneError> for PowerpcRuntimeError { // use super::SahneError is assumed correct path
    fn from(err: super::SahneError) -> Self {
        PowerpcRuntimeError::InitializationError(err)
    }
}

impl std::error::Error for PowerpcRuntimeError {} // Implement Error trait

impl std::fmt::Display for PowerpcRuntimeError { // Implement Display trait
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         match self {
             PowerpcRuntimeError::InitializationError(e) => {
                 write!(f, "PowerPC çalışma zamanı başlatma hatası: {:?}", e)
             }
             PowerpcRuntimeError::CodeLoadError(msg) => {
                 write!(f, "PowerPC kod yükleme hatası: {}", msg)
             }
             PowerpcRuntimeError::ExecutionError(arch_error) => {
                 write!(f, "PowerPC yürütme hatası: {}", arch_error) // PowerpcArchitectureError'ın Display implementasyonunu kullanır
             }
             PowerpcRuntimeError::UnexpectedTermination => {
                 write!(f, "PowerPC yürütme beklenmedik şekilde sonlandı.")
             }
             PowerpcRuntimeError::ExecutionCompleted(code) => {
                 write!(f, "PowerPC yürütme başarıyla tamamlandı. Çıkış kodu: {}", code)
             }
         }
     }
}


pub struct PowerpcRuntime {
    architecture: PowerpcArchitecture,
    standard_library: StandardLibrary, // Standart kütüphane örneği
    // Çalışma zamanı durumu (registerlar, bellek, program sayacı) artık PowerpcArchitecture içinde tutuluyor.
}

impl PowerpcRuntime {
    /// Yeni bir PowerpcRuntime örneği oluşturur ve VM belleğini tahsis eder.
    ///
    /// # Arguments
    /// * `vm_memory_size` - VM için ayrılacak bellek boyutu.
    /// * `standard_library` - VM tarafından kullanılacak StandardLibrary instance'ı.
    ///
    /// Sahne64 bellek tahsisi veya PowerpcArchitecture başlatma başarısız olursa `PowerpcRuntimeError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, PowerpcRuntimeError> { // Return type changed
         println!("PowerPC Runtime başlatılıyor...");

         // PowerpcArchitecture artık new fonksiyonunda bellek tahsisini yapıyor.
         // StandardLibrary'yi de PowerpcArchitecture'a geçirmeliyiz.
        let architecture = PowerpcArchitecture::new(vm_memory_size, standard_library.clone())?; // PowerpcArchitecture::new Result<Self, SahneError> döner, From implementasyonu kullanılır. StandardLibrary clone edilebilir olmalı.

         println!("PowerPC Runtime başarıyla başlatıldı. Bellek boyutu: {} byte", architecture.vm_memory_size); // Boyutu architecture'dan al

        Ok(PowerpcRuntime {
             architecture,
             standard_library, // StandardLibrary'nin bir kopyası architecture'da, asıl instance burada tutulur.
        })
    }

    // PowerPC kodu yürütür.
    // Başarılı olursa Ok(i32) döner (çıkış kodu), hata oluşursa Err(PowerpcRuntimeError) döner.
    pub fn run(&mut self, code: &[u8]) -> Result<i32, PowerpcRuntimeError> { // Return type changed (i32 for exit code)
        println!("PowerPC kodu VM belleğine yüklemeye başlanıyor...");

        // Yürütülecek kodu VM belleğine yükle.
        // PowerpcArchitecture içinde bellek erişim helperları olmalı (write_memory_slice).
        let code_size = code.len();
        if code_size > self.architecture.vm_memory_size {
             // Kodu yüklemek için VM belleği yeterli değil.
             eprintln!("Hata: Yüklenen kod VM belleğinden büyük (Kod boyutu: {}, Bellek boyutu: {})", code_size, self.architecture.vm_memory_size);
             return Err(PowerpcRuntimeError::CodeLoadError(format!("Code size ({}) exceeds VM memory size ({})", code_size, self.architecture.vm_memory_size)));
        }

        // Kodu VM belleğinin başlangıcına yaz.
        // write_memory_slice 0 adresine yazmaya çalışacaktır.
        match self.architecture.write_memory_slice(0, code) { // write_memory_slice should be in architecture
            Ok(_) => {
                println!("PowerPC kodu VM belleğine başarıyla yüklendi ({} byte).", code_size);
                // Program sayacını kodun başlangıcına ayarla (genellikle 0). PowerPC entry point genellikle 0.
                self.architecture.set_pc(0)?; // set_pc should be in architecture
            }
             Err(e) => {
                 // Belleğe yazma hatası (PowerpcArchitectureError)
                  eprintln!("Hata: Kodu VM belleğine yazarken hata oluştu: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                  return Err(e.into()); // PowerpcArchitectureError -> RuntimeError::ExecutionError
             }
        }

        println!("PowerPC yürütme döngüsü başlatılıyor...");

        // VM yürütme döngüsü
        // execute_next_instruction PC'deki komutu yürütür, PC'yi ilerletir ve durumu günceller.
        // Başarı döner veya bir hata (illegal instruction, bellek hatası, syscall vb.) döner.
        // Exit syscall'u veya komutu özel olarak ele alınmalıdır (architecture tarafından sinyal verilir).

        loop {
             // Orijinaldeki placeholder output mantığı ve architecture.execute_instruction(code) kaldırıldı.
            // Yerine PowerpcArchitecture::execute_next_instruction() çağrılacak.
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
                              return Err(PowerpcRuntimeError::ExecutionError(PowerpcArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                         }
                     }
                    // Şimdilik, execute_next_instruction() sadece Result<()> dönüyor ve exit/breakpoint
                    // hatalarını PowerpcArchitectureError olarak döndürüyor varsayalım (ARM runtime örneğindeki gibi).
                    // Eğer Ok dönerse, döngü devam eder.

                    // Eğer PowerpcArchitecture::execute_next_instruction'dan Ok dönüyorsa ve bu bir exit sinyali değilse...
                    // Döngü devam eder.
                }
                // PowerpcArchitectureError içinden Exit veya Breakpoint gibi özel durumları yakala
                 Err(PowerpcArchitectureError::ExecutionError(msg)) if msg.starts_with("Exit with code:") => {
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
                     return Err(PowerpcRuntimeError::ExecutionError(PowerpcArchitectureError::ExecutionError(format!("Invalid exit message format: {}", msg))));
                }
                Err(PowerpcArchitectureError::ExecutionError(msg)) if msg == "Breakpoint reached" => {
                     println!("VM breakpoint'e ulaştı.");
                     // Breakpoint durumunda dur ve bir hata olarak bildir.
                     return Err(PowerpcRuntimeError::ExecutionError(PowerpcArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                }
                 Err(e) => {
                     // execute_next_instruction'dan dönen diğer hatalar (IllegalInstruction, MemoryAccessError, SystemCallError vb.)
                     eprintln!("PowerPC yürütme hatası: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                     return Err(e.into()); // PowerpcArchitectureError -> RuntimeError::ExecutionError
                }
            }
        }

         // Eğer döngü hiçbir zaman sonlanmazsa (exit/hata olmadan), buraya unreachable! eklenebilir
         // veya bir timeout mekanizması olabilir.
          Ok(0) // Bu satıra normalde erişilmemeli
    }
}
