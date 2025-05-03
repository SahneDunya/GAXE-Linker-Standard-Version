use crate::arch_openrisc::OpenriscArchitecture;
use crate::arch_openrisc::OpenriscArchitectureError; // OpenRISC mimarisine özgü hata türü

// Sahne64 memory modülünü artık doğrudan runtime değil, Architecture kullanacak
// use super::memory; // Kaldırıldı

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
pub enum OpenriscRuntimeError {
     /// Çalışma zamanı başlatılırken Sahne64 kaynaklı bir hata oluştu.
     InitializationError(SahneError), // MemoryError veya IOError yerine daha genel
    /// VM belleğine kod yüklenirken hata oluştu.
    CodeLoadError(String),
    /// OpenRISC mimarisi yürütülürken bir hata oluştu.
    ExecutionError(OpenriscArchitectureError), // String yerine OpenriscArchitectureError'ı kapsar
    /// VM'in yürütme döngüsü beklenmedik şekilde sonlandı (örn. exit komutu olmadan).
    UnexpectedTermination,
    /// VM başarılı bir şekilde yürütmeyi tamamladı (örn. exit komutu ile), çıkış kodu ile birlikte.
    ExecutionCompleted(i32), // Exit code
    // OpenriscRuntimeError'ın orijinal varyantları (ExecutionError(String), MemoryError(SahneError), IOError(SahneError))
    // artık OpenriscArchitectureError içinde veya InitializationError içinde detaylandırılmalıdır.
     MemoryError(SahneError) -> InitializationError(SahneError) veya OpenriscArchitectureError::MemoryAccessError (eğer execution sırasında olursa)
     IOError(SahneError) -> InitializationError(SahneError) veya OpenriscArchitectureError::SystemCallError (eğer syscall sırasında olursa)
     ExecutionError(String) -> OpenriscArchitectureError::ExecutionError (daha genel mimari hata)
    // Diğer mimariye özgü hatalar OpenriscArchitectureError'a taşınmalıdır.
}

// OpenriscArchitectureError'dan OpenriscRuntimeError::ExecutionError'a dönüşüm
impl From<OpenriscArchitectureError> for OpenriscRuntimeError {
    fn from(err: OpenriscArchitectureError) -> Self {
        OpenriscRuntimeError::ExecutionError(err)
    }
}

// SahneError'dan OpenriscRuntimeError::InitializationError'a dönüşüm
// OpenriscArchitecture::new veya runtime::new içindeki diğer Sahne64 çağrıları için.
impl From<super::SahneError> for OpenriscRuntimeError { // use super::SahneError is assumed correct path
    fn from(err: super::SahneError) -> Self {
         // Orijinaldeki match yerine tüm SahneError'ları başlatma hatası olarak ele alalım.
         // Yürütme sırasındaki SahneError'lar mimari tarafından yakalanıp OpenriscArchitectureError içine sarılmalıdır.
        OpenriscRuntimeError::InitializationError(err)
    }
}

impl std::error::Error for OpenriscRuntimeError {} // Implement Error trait

impl std::fmt::Display for OpenriscRuntimeError { // Implement Display trait
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         match self {
             OpenriscRuntimeError::InitializationError(e) => {
                 write!(f, "OpenRISC çalışma zamanı başlatma hatası: {:?}", e)
             }
             OpenriscRuntimeError::CodeLoadError(msg) => {
                 write!(f, "OpenRISC kod yükleme hatası: {}", msg)
             }
             OpenriscRuntimeError::ExecutionError(arch_error) => {
                 write!(f, "OpenRISC yürütme hatası: {}", arch_error) // OpenriscArchitectureError'ın Display implementasyonunu kullanır
             }
             OpenriscRuntimeError::UnexpectedTermination => {
                 write!(f, "OpenRISC yürütme beklenmedik şekilde sonlandı.")
             }
             OpenriscRuntimeError::ExecutionCompleted(code) => {
                 write!(f, "OpenRISC yürütme başarıyla tamamlandı. Çıkış kodu: {}", code)
             }
         }
     }
}


pub struct OpenriscRuntime {
    architecture: OpenriscArchitecture,
    standard_library: StandardLibrary, // Standart kütüphane örneği
}

impl OpenriscRuntime {
    /// Yeni bir OpenriscRuntime örneği oluşturur ve VM belleğini tahsis eder.
    ///
    /// # Arguments
    /// * `vm_memory_size` - VM için ayrılacak bellek boyutu.
    /// * `standard_library` - VM tarafından kullanılacak StandardLibrary instance'ı.
    ///
    /// Sahne64 bellek tahsisi veya OpenriscArchitecture başlatma başarısız olursa `OpenriscRuntimeError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, OpenriscRuntimeError> { // Return type changed
         println!("OpenRISC Runtime başlatılıyor...");

         // OpenriscArchitecture artık new fonksiyonında bellek tahsisini yapıyor.
         // StandardLibrary'yi de OpenriscArchitecture'a geçirmeliyiz.
        let architecture = OpenriscArchitecture::new(vm_memory_size, standard_library.clone())?; // OpenriscArchitecture::new Result<Self, SahneError> döner, From implementasyonu kullanılır. StandardLibrary clone edilebilir olmalı.

         println!("OpenRISC Runtime başarıyla başlatıldı. Bellek boyutu: {} byte", architecture.vm_memory_size); // Boyutu architecture'dan al

        Ok(OpenriscRuntime {
             architecture,
             standard_library, // StandardLibrary'nin bir kopyası architecture'da, asıl instance burada tutulur.
        })
    }

    /// OpenRISC makine kodunu VM belleğine yükler ve yürütmeye başlar.
    ///
    /// # Arguments
    /// * `code` - Yürütülecek makine kodu baytları.
    ///
    /// VM yürütme durumu veya hatası döndürür (çıkış kodu veya hata).
    pub fn run(&mut self, code: &[u8]) -> Result<i32, OpenriscRuntimeError> { // Return type changed (i32 for exit code)
        println!("OpenRISC kodu VM belleğine yüklemeye başlanıyor...");

        // Yürütülecek kodu VM belleğine yükle.
        // OpenriscArchitecture içinde bellek erişim helperları olmalı (write_memory_slice).
        let code_size = code.len();
        if code_size > self.architecture.vm_memory_size {
             // Kodu yüklemek için VM belleği yeterli değil.
             eprintln!("Hata: Yüklenen kod VM belleğinden büyük (Kod boyutu: {}, Bellek boyutu: {})", code_size, self.architecture.vm_memory_size);
             return Err(OpenriscRuntimeError::CodeLoadError(format!("Code size ({}) exceeds VM memory size ({})", code_size, self.architecture.vm_memory_size)));
        }

        // Kodu VM belleğinin başlangıcına yaz.
        // write_memory_slice 0 adresine yazmaya çalışacaktır.
        match self.architecture.write_memory_slice(0, code) { // write_memory_slice should be in architecture
            Ok(_) => {
                println!("OpenRISC kodu VM belleğine başarıyla yüklendi ({} byte).", code_size);
                // Program sayacını kodun başlangıcına ayarla (genellikle 0).
                self.architecture.set_pc(0)?; // set_pc should be in architecture
            }
             Err(e) => {
                 // Belleğe yazma hatası (OpenriscArchitectureError)
                  eprintln!("Hata: Kodu VM belleğine yazarken hata oluştu: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                  return Err(e.into()); // OpenriscArchitectureError -> RuntimeError::ExecutionError
             }
        }


        println!("OpenRISC yürütme döngüsü başlatılıyor...");

        // VM yürütme döngüsü
        // execute_next_instruction PC'deki komutu yürütür, PC'yi ilerletir ve durumu günceller.
        // Başarı döner veya bir hata (illegal instruction, bellek hatası, syscall vb.) döner.
        // Exit syscall'u veya komutu özel olarak ele alınmalıdır (architecture tarafından sinyal verilir).

        loop {
            // OpenriscArchitecture::execute_instruction(code) çağrısı kaldırıldı.
            // Yerine OpenriscArchitecture::execute_next_instruction() çağrılacak.
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
                              return Err(OpenriscRuntimeError::ExecutionError(OpenriscArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                         }
                     }
                     // Şimdilik, execute_next_instruction() sadece Result<()> dönüyor ve exit/breakpoint
                     // hatalarını OpenriscArchitectureError olarak döndürüyor varsayalım (ARM runtime örneğindeki gibi).
                     // Eğer Ok dönerse, döngü devam eder.

                    // Eğer OpenriscArchitecture::execute_next_instruction'dan Ok dönüyorsa ve bu bir exit sinyali değilse...
                    // Döngü devam eder.
                }
                // OpenriscArchitectureError içinden Exit veya Breakpoint gibi özel durumları yakala
                 Err(OpenriscArchitectureError::ExecutionError(msg)) if msg.starts_with("Exit with code:") => {
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
                     return Err(OpenriscRuntimeError::ExecutionError(OpenriscArchitectureError::ExecutionError(format!("Invalid exit message format: {}", msg))));
                }
                Err(OpenriscArchitectureError::ExecutionError(msg)) if msg == "Breakpoint reached" => {
                     println!("VM breakpoint'e ulaştı.");
                     // Breakpoint durumunda dur ve bir hata olarak bildir.
                     return Err(OpenriscRuntimeError::ExecutionError(OpenriscArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                }
                 Err(e) => {
                     // execute_next_instruction'dan dönen diğer hatalar (IllegalInstruction, MemoryAccessError, SystemCallError vb.)
                     eprintln!("OpenRISC yürütme hatası: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                     return Err(e.into()); // OpenriscArchitectureError -> RuntimeError::ExecutionError
                }
            }
        }

        // Eğer döngü hiçbir zaman sonlanmazsa (exit/hata olmadan), buraya unreachable! eklenebilir
        // veya bir timeout mekanizması olabilir.
         Ok(0) // Bu satıra normalde erişilmemeli
    }

    // Diğer çalışma zamanı fonksiyonları eklenebilir.
    // Örneğin: get_register, set_register, read_memory, write_memory gibi (architecture'dan çağrılarak)
    // get_pc (architecture'dan)
    // Syscall handling (architecture içinde)
    // ...
}
