use crate::arch_x86::X86Architecture;
use crate::arch_x86::X86ArchitectureError; // x86 mimarisine özgü hata türü

// Sahne64 hata türünü içeri aktar (Sahne64 API'sından dönebilir)
use super::SahneError; // (varsa crate::SahneError olarak değiştirin)

// Standard kütüphaneyi kullanmak için
use crate::standard_library::StandardLibrary;

// Diğer gerekli Rust core/alloc kütüphane elemanları
use alloc::string::String;
use alloc::format;
use alloc::vec::Vec; // Often needed indirectly

// X86 çalışma zamanı hataları için özel hata türü
#[derive(Debug)] // fmt::Display de burada derive edilebilir
pub enum X86RuntimeError {
     /// Çalışma zamanı başlatılırken Sahne64 kaynaklı bir hata oluştu.
     InitializationError(SahneError),
    /// VM belleğine kod yüklenirken hata oluştu.
    CodeLoadError(String),
    /// x86 mimarisi yürütülürken bir hata oluştu.
    ExecutionError(X86ArchitectureError), // String yerine X86ArchitectureError'ı kapsar
    /// VM'in yürütme döngüsü beklenmedik şekilde sonlandı (örn. exit komutu olmadan).
    UnexpectedTermination,
    /// VM başarılı bir şekilde yürütmeyi tamamladı (örn. exit komutu ile), çıkış kodu ile birlikte.
    ExecutionCompleted(i32), // Exit code
    // Orijinal koddaki String hatalar artık X86ArchitectureError içinde detaylandırılmalıdır.
    // Örneğin: Illegal instruction, Invalid operand, Syscall errors etc.
}

// X86ArchitectureError'dan X86RuntimeError::ExecutionError'a dönüşüm
impl From<X86ArchitectureError> for X86RuntimeError {
    fn from(err: X86ArchitectureError) -> Self {
        X86RuntimeError::ExecutionError(err)
    }
}

// SahneError'dan X86RuntimeError::InitializationError'a dönüşüm
// X86Architecture::new veya runtime::new içindeki diğer Sahne64 çağrıları için.
impl From<super::SahneError> for X86RuntimeError { // use super::SahneError is assumed correct path
    fn from(err: super::SahneError) -> Self {
        X86RuntimeError::InitializationError(err)
    }
}

impl std::error::Error for X86RuntimeError {} // Implement Error trait

impl std::fmt::Display for X86RuntimeError { // Implement Display trait
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         match self {
             X86RuntimeError::InitializationError(e) => {
                 write!(f, "X86 çalışma zamanı başlatma hatası: {:?}", e)
             }
             X86RuntimeError::CodeLoadError(msg) => {
                 write!(f, "X86 kod yükleme hatası: {}", msg)
             }
             X86RuntimeError::ExecutionError(arch_error) => {
                 write!(f, "X86 yürütme hatası: {}", arch_error) // X86ArchitectureError'ın Display implementasyonunu kullanır
             }
             X86RuntimeError::UnexpectedTermination => {
                 write!(f, "X86 yürütme beklenmedik şekilde sonlandı.")
             }
             X86RuntimeError::ExecutionCompleted(code) => {
                 write!(f, "X86 yürütme başarıyla tamamlandı. Çıkış kodu: {}", code)
             }
         }
     }
}


pub struct X86Runtime {
    architecture: X86Architecture,
    standard_library: StandardLibrary, // Standart kütüphane örneği
}

impl X86Runtime {
    /// Yeni bir X86Runtime örneği oluşturur ve VM belleğini tahsis eder.
    ///
    /// # Arguments
    /// * `vm_memory_size` - VM için ayrılacak bellek boyutu.
    /// * `standard_library` - VM tarafından kullanılacak StandardLibrary instance'ı.
    ///
    /// Sahne64 bellek tahsisi veya X86Architecture başlatma başarısız olursa `X86RuntimeError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, X86RuntimeError> { // Return type changed
         println!("X86 Runtime başlatılıyor...");

         // X86Architecture artık new fonksiyonında bellek tahsisini yapıyor.
         // StandardLibrary'yi de X86Architecture'a geçirmeliyiz.
        let architecture = X86Architecture::new(vm_memory_size, standard_library.clone())?; // X86Architecture::new Result<Self, SahneError> döner, From implementasyonu kullanılır. StandardLibrary clone edilebilir olmalı.

         println!("X86 Runtime başarıyla başlatıldı. Bellek boyutu: {} byte", architecture.vm_memory_size); // Boyutu architecture'dan al

        Ok(X86Runtime {
             architecture,
             standard_library, // StandardLibrary'nin bir kopyası architecture'da, asıl instance burada tutulur.
        })
    }

    pub fn run(&mut self, code: &[u8]) -> Result<i32, X86RuntimeError> { // Return type changed (i32 for exit code)
        println!("X86 kodu VM belleğine yüklemeye başlanıyor...");

        // Yürütülecek kodu VM belleğine yükle.
        // X86Architecture içinde bellek erişim helperları olmalı (write_memory_slice).
        let code_size = code.len();
        if code_size > self.architecture.vm_memory_size {
             // Kodu yüklemek için VM belleği yeterli değil.
             eprintln!("Hata: Yüklenen kod VM belleğinden büyük (Kod boyutu: {}, Bellek boyutu: {})", code_size, self.architecture.vm_memory_size);
             return Err(X86RuntimeError::CodeLoadError(format!("Code size ({}) exceeds VM memory size ({})", code_size, self.architecture.vm_memory_size)));
        }

        // Kodu VM belleğinin başlangıcına yaz.
        // write_memory_slice 0 adresine yazmaya çalışacaktır.
        match self.architecture.write_memory_slice(0, code) { // write_memory_slice should be in architecture
            Ok(_) => {
                println!("X86 kodu VM belleğine başarıyla yüklendi ({} byte).", code_size);
                // Program sayacını kodun başlangıcına ayarla (genellikle 0).
                self.architecture.set_pc(0)?; // set_pc should be in architecture
            }
             Err(e) => {
                 // Belleğe yazma hatası (X86ArchitectureError)
                  eprintln!("Hata: Kodu VM belleğine yazarken hata oluştu: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                  return Err(e.into()); // X86ArchitectureError -> RuntimeError::ExecutionError
             }
        }


        println!("X86 yürütme döngüsü başlatılıyor...");

        // VM yürütme döngüsü
        // execute_next_instruction PC'deki komutu yürütür, PC'yi ilerletir ve durumu günceller.
        // Başarı döner veya bir hata (illegal instruction, bellek hatası, syscall vb.) döner.
        // Exit syscall'u veya komutu özel olarak ele alınmalıdır (architecture tarafından sinyal verilir).

        loop {
             // Orijinaldeki memory status print logic ve architecture.execute_instruction(code) kaldırıldı.
            // Yerine X86Architecture::execute_next_instruction() çağrılacak.
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
                              return Err(X86RuntimeError::ExecutionError(X86ArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                         }
                     }
                     // Şimdilik, execute_next_instruction() sadece Result<()> dönüyor ve exit/breakpoint
                     // hatalarını X86ArchitectureError olarak döndürüyor varsayalım (ARM runtime örneğindeki gibi).
                     // Eğer Ok dönerse, döngü devam eder.

                    // Eğer X86Architecture::execute_next_instruction'dan Ok dönüyorsa ve bu bir exit sinyali değilse...
                    // Döngü devam eder.
                }
                // X86ArchitectureError içinden Exit veya Breakpoint gibi özel durumları yakala
                 Err(X86ArchitectureError::ExecutionError(msg)) if msg.starts_with("Exit with code:") => {
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
                     return Err(X86RuntimeError::ExecutionError(X86ArchitectureError::ExecutionError(format!("Invalid exit message format: {}", msg))));
                }
                Err(X86ArchitectureError::ExecutionError(msg)) if msg == "Breakpoint reached" => {
                     println!("VM breakpoint'e ulaştı.");
                     // Breakpoint durumunda dur ve bir hata olarak bildir.
                     return Err(X86RuntimeError::ExecutionError(X86ArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                }
                 Err(e) => {
                     // execute_next_instruction'dan dönen diğer hatalar (IllegalInstruction, MemoryAccessError, SystemCallError vb.)
                     eprintln!("X86 yürütme hatası: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                     return Err(e.into()); // X86ArchitectureError -> RuntimeError::ExecutionError
                }
            }
        }

         // Eğer döngü hiçbir zaman sonlanmazsa (exit/hata olmadan), buraya unreachable! eklenebilir
         // veya bir timeout mekanizması olabilir.
          Ok(0) // Bu satıra normalde erişilmemeli
    }
}
