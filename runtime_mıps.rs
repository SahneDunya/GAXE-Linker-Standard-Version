use crate::arch_mips::MipsArchitecture;
use crate::arch_mips::MipsArchitectureError; // MIPS mimarisine özgü hata türü

// Sahne64 hata türünü içeri aktar (Sahne64 API'sından dönebilir)
use super::SahneError; // (varsa crate::SahneError olarak değiştirin)

// Standard kütüphaneyi kullanmak için
use crate::standard_library::StandardLibrary;

// Diğer gerekli Rust core/alloc kütüphane elemanları
use alloc::string::String;
use alloc::format;
use alloc::vec::Vec; // Often needed indirectly

// Özel hata türü tanımla
#[derive(Debug)] // fmt::Display de burada derive edilebilir
pub enum MipsRuntimeError {
    /// Çalışma zamanı başlatılırken Sahne64 kaynaklı bir hata oluştu.
    InitializationError(SahneError), // MemoryError(SahneError) yerine daha genel
    /// VM belleğine kod yüklenirken hata oluştu.
    CodeLoadError(String),
    /// MIPS mimarisi yürütülürken bir hata oluştu.
    ExecutionError(MipsArchitectureError), // String yerine MipsArchitectureError'ı kapsar
    /// VM'in yürütme döngüsü beklenmedik şekilde sonlandı (örn. exit komutu olmadan).
    UnexpectedTermination,
    /// VM başarılı bir şekilde yürütmeyi tamamladı (örn. exit komutu ile), çıkış kodu ile birlikte.
    ExecutionCompleted(i32), // Exit code
    // MipsRuntimeError'ın orijinal varyantları (ExecutionError(String), InitializationError(String), UnsupportedOperation(String), MemoryError(SahneError))
    // artık MipsArchitectureError içinde veya InitializationError içinde detaylandırılmalıdır.
    MemoryError(SahneError) -> InitializationError(SahneError) veya ElbrusArchitectureError::MemoryAccessError (eğer execution sırasında olursa)
    InitializationError(String) -> Artık InitializationError(SahneError) yeterli olabilir veya ek hata türleri eklenebilir
    UnsupportedOperation(String) -> MipsArchitectureError::UnsupportedInstruction/Operation (execution sırasında)
}

// MipsArchitectureError'dan MipsRuntimeError::ExecutionError'a dönüşüm
impl From<MipsArchitectureError> for MipsRuntimeError {
    fn from(err: MipsArchitectureError) -> Self {
        MipsRuntimeError::ExecutionError(err)
    }
}

// SahneError'dan MipsRuntimeError::InitializationError'a dönüşüm
// MipsArchitecture::new veya runtime::new içindeki diğer Sahne64 çağrıları için.
impl From<super::SahneError> for MipsRuntimeError { // use super::SahneError is assumed correct path
    fn from(err: super::SahneError) -> Self {
        MipsRuntimeError::InitializationError(err)
    }
}

impl std::error::Error for MipsRuntimeError {} // Implement Error trait

impl std::fmt::Display for MipsRuntimeError { // Implement Display trait
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         match self {
             MipsRuntimeError::InitializationError(e) => {
                 write!(f, "MIPS çalışma zamanı başlatma hatası: {:?}", e)
             }
             MipsRuntimeError::CodeLoadError(msg) => {
                 write!(f, "MIPS kod yükleme hatası: {}", msg)
             }
             MipsRuntimeError::ExecutionError(arch_error) => {
                 write!(f, "MIPS yürütme hatası: {}", arch_error) // MipsArchitectureError'ın Display implementasyonunu kullanır
             }
             MipsRuntimeError::UnexpectedTermination => {
                 write!(f, "MIPS yürütme beklenmedik şekilde sonlandı.")
             }
             MipsRuntimeError::ExecutionCompleted(code) => {
                 write!(f, "MIPS yürütme başarıyla tamamlandı. Çıkış kodu: {}", code)
             }
         }
     }
}


pub struct MipsRuntime {
    architecture: MipsArchitecture,
    standard_library: StandardLibrary, // Standart kütüphane örneği
}

impl MipsRuntime {
    /// Yeni bir MipsRuntime örneği oluşturur ve VM belleğini tahsis eder.
    ///
    /// # Arguments
    /// * `vm_memory_size` - VM için ayrılacak bellek boyutu.
    /// * `standard_library` - VM tarafından kullanılacak StandardLibrary instance'ı.
    ///
    /// Sahne64 bellek tahsisi veya MipsArchitecture başlatma başarısız olursa `MipsRuntimeError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, MipsRuntimeError> { // Return type changed
         println!("MIPS Çalışma Zamanı Başlatılıyor...");

         // MipsArchitecture artık new fonksiyonunda bellek tahsisini yapıyor.
         // StandardLibrary'yi de MipsArchitecture'a geçirmeliyiz.
        let architecture = MipsArchitecture::new(vm_memory_size, standard_library.clone())?; // MipsArchitecture::new Result<Self, SahneError> döner, From implementasyonu kullanılır. StandardLibrary clone edilebilir olmalı.

         println!("MIPS Çalışma Zamanı Başarıyla Başlatıldı. Bellek boyutu: {} byte", architecture.vm_memory_size); // Boyutu architecture'dan al

        Ok(MipsRuntime {
             architecture,
             standard_library, // StandardLibrary'nin bir kopyası architecture'da, asıl instance burada tutulur.
        })
    }
    
 /// MIPS makine kodunu VM belleğine yükler ve yürütmeye başlar.
    ///
    /// # Arguments
    /// * `code` - Yürütülecek makine kodu baytları.
    ///
    /// VM yürütme durumu veya hatası döndürür (çıkış kodu veya hata).
    pub fn run(&mut self, code: &[u8]) -> Result<i32, MipsRuntimeError> { // Return type changed (i32 for exit code)
        println!("MIPS kodu VM belleğine yüklemeye başlanıyor...");

        // Yürütülecek kodu VM belleğine yükle.
        // MipsArchitecture içinde bellek erişim helperları olmalı (write_memory_slice).
        let code_size = code.len();
        if code_size > self.architecture.vm_memory_size {
             // Kodu yüklemek için VM belleği yeterli değil.
             eprintln!("Hata: Yüklenen kod VM belleğinden büyük (Kod boyutu: {}, Bellek boyutu: {})", code_size, self.architecture.vm_memory_size);
             return Err(MipsRuntimeError::CodeLoadError(format!("Code size ({}) exceeds VM memory size ({})", code_size, self.architecture.vm_memory_size)));
        }

        // Kodu VM belleğinin başlangıcına yaz.
        // write_memory_slice 0 adresine yazmaya çalışacaktır.
        match self.architecture.write_memory_slice(0, code) { // write_memory_slice should be in architecture
            Ok(_) => {
                println!("MIPS kodu VM belleğine başarıyla yüklendi ({} byte).", code_size);
                // Program sayacını kodun başlangıcına ayarla (genellikle 0).
                self.architecture.set_pc(0)?; // set_pc should be in architecture
            }
             Err(e) => {
                 // Belleğe yazma hatası (MipsArchitectureError)
                  eprintln!("Hata: Kodu VM belleğine yazarken hata oluştu: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                  return Err(e.into()); // MipsArchitectureError -> RuntimeError::ExecutionError
             }
        }


        println!("MIPS yürütme döngüsü başlatılıyor...");

        // VM yürütme döngüsü
        // execute_next_instruction PC'deki komutu yürütür, PC'yi ilerletir ve durumu günceller.
        // Başarı döner veya bir hata (illegal instruction, bellek hatası vb.) döner.
        // Exit syscall'u veya komutu özel olarak ele alınmalıdır (architecture tarafından sinyal verilir).

        loop {
            // MipsArchitecture::execute_instruction(code) çağrısı kaldırıldı.
            // Yerine MipsArchitecture::execute_next_instruction() çağrılacak.
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
                              return Err(MipsRuntimeError::ExecutionError(MipsArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                         }
                     }
                     // Şimdilik, execute_next_instruction() sadece Result<()> dönüyor ve exit/breakpoint
                     // hatalarını MipsArchitectureError olarak döndürüyor varsayalım (ARM runtime örneğindeki gibi).
                     // Eğer Ok dönerse, döngü devam eder.

                    // Eğer MipsArchitecture::execute_next_instruction'dan Ok dönüyorsa ve bu bir exit sinyali değilse...
                    // Döngü devam eder.
                }
                // MipsArchitectureError içinden Exit veya Breakpoint gibi özel durumları yakala
                 Err(MipsArchitectureError::ExecutionError(msg)) if msg.starts_with("Exit with code:") => {
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
                     return Err(MipsRuntimeError::ExecutionError(MipsArchitectureError::ExecutionError(format!("Invalid exit message format: {}", msg))));
                }
                Err(MipsArchitectureError::ExecutionError(msg)) if msg == "Breakpoint reached" => {
                     println!("VM breakpoint'e ulaştı.");
                     // Breakpoint durumunda dur ve bir hata olarak bildir.
                     return Err(MipsRuntimeError::ExecutionError(MipsArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                }
                 Err(e) => {
                     // execute_next_instruction'dan dönen diğer hatalar (IllegalInstruction, MemoryAccessError, SystemCallError vb.)
                     eprintln!("MIPS yürütme hatası: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                     return Err(e.into()); // MipsArchitectureError -> RuntimeError::ExecutionError
                }
            }
        }

        // Eğer döngü hiçbir zaman sonlanmazsa (exit/hata olmadan), buraya unreachable! eklenebilir
        // veya bir timeout mekanizması olabilir.
         Ok(0) // Bu satıra normalde erişilmemeli
    }

    // Diğer MIPS çalışma zamanı fonksiyonları... (gerektiğinde eklenebilir)
    // Örneğin: get_register, set_register, read_memory, write_memory gibi (architecture'dan çağrılarak)
    // get_pc (architecture'dan)
    // ...
}
