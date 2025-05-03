use crate::arch_arm::ArmArchitecture;
use crate::arch_arm::ArmArchitectureError;

// Sahne64 memory modülünü içeri aktar (VM belleği yönetimi için)
use crate::memory as sahne_memory; // Alias memory to avoid conflict if needed

// Sahne64 hata türünü içeri aktar (Sahne64 API'sından dönebilir)
use crate::SahneError;

// Standard kütüphaneyi kullanmak için
use crate::standard_library::StandardLibrary;

// Diğer gerekli Rust core/alloc kütüphane elemanları
use alloc::string::String;
use alloc::format;
use alloc::vec::Vec; // Often needed indirectly


// Çalışma zamanı hataları için özel hata türü
#[derive(Debug)]
pub enum ArmRuntimeError {
    /// Çalışma zamanı başlatılırken Sahne64 kaynaklı bir hata oluştu.
    InitializationError(SahneError),
    /// VM belleğine kod yüklenirken hata oluştu.
    CodeLoadError(String),
    /// ARM mimarisi yürütülürken bir hata oluştu.
    ExecutionError(ArmArchitectureError),
    /// VM'in yürütme döngüsü beklenmedik şekilde sonlandı (örn. exit komutu olmadan).
    UnexpectedTermination,
    /// VM başarılı bir şekilde yürütmeyi tamamladı (örn. exit komutu ile), çıkış kodu ile birlikte.
    ExecutionCompleted(i32), // Exit code
    // ... diğer çalışma zamanı hata varyantları eklenebilir ...
}

// ArmArchitectureError'dan ArmRuntimeError::ExecutionError'a dönüşüm
impl From<ArmArchitectureError> for ArmRuntimeError {
    fn from(err: ArmArchitectureError) -> Self {
        ArmRuntimeError::ExecutionError(err)
    }
}

// SahneError'dan ArmRuntimeError::InitializationError'a dönüşüm
// ArmArchitecture::new veya runtime::new içindeki diğer Sahne64 çağrıları için.
impl From<SahneError> for ArmRuntimeError {
    fn from(err: SahneError) -> Self {
        ArmRuntimeError::InitializationError(err)
    }
}


impl std::error::Error for ArmRuntimeError {}

impl std::fmt::Display for ArmRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
             ArmRuntimeError::InitializationError(e) => {
                 write!(f, "ARM çalışma zamanı başlatma hatası: {:?}", e)
             }
             ArmRuntimeError::CodeLoadError(msg) => {
                 write!(f, "ARM kod yükleme hatası: {}", msg)
             }
             ArmRuntimeError::ExecutionError(arch_error) => {
                 write!(f, "ARM yürütme hatası: {}", arch_error) // ArmArchitectureError'ın Display implementasyonunu kullanır
             }
             ArmRuntimeError::UnexpectedTermination => {
                 write!(f, "ARM yürütme beklenmedik şekilde sonlandı.")
             }
             ArmRuntimeError::ExecutionCompleted(code) => {
                 write!(f, "ARM yürütme başarıyla tamamlandı. Çıkış kodu: {}", code)
             }
             // ... diğer hata varyantları için formatlama eklenebilir ...
        }
    }
}


pub struct ArmRuntime {
    architecture: ArmArchitecture,
    standard_library: StandardLibrary, // Standart kütüphane örneği
    // ARM çalışma zamanının durumu için ek alanlar:
    // Örneğin, registerlar, bellek, program sayacı, vb.
    // Bu alanlar artık ArmArchitecture içinde tutuluyor.
}

impl ArmRuntime {
    /// Yeni bir ArmRuntime örneği oluşturur ve VM belleğini tahsis eder.
    ///
    /// # Arguments
    /// * `vm_memory_size` - VM için ayrılacak bellek boyutu.
    /// * `standard_library` - VM tarafından kullanılacak StandardLibrary instance'ı.
    ///
    /// Sahne64 bellek tahsisi başarısız olursa `ArmRuntimeError::InitializationError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, ArmRuntimeError> {
         println!("ARM çalışma zamanı başlatılıyor...");

         // ArmArchitecture artık new fonksiyonunda bellek tahsisini yapıyor.
         // StandardLibrary'yi de ArmArchitecture'a geçirmeliyiz.
        let architecture = ArmArchitecture::new(vm_memory_size, standard_library.clone())?; // ArmArchitecture::new SahneError döner, From implementasyonu ile RuntimeError'a çevrilir. StandardLibrary clone edilebilir olmalı.

         println!("ARM çalışma zamanı başarıyla başlatıldı.");

        Ok(ArmRuntime {
             architecture,
             standard_library, // StandardLibrary'nin bir kopyası architecture'da, asıl instance burada tutulur.
        })
    }

    /// ARM makine kodunu VM belleğine yükler ve yürütmeye başlar.
    ///
    /// # Arguments
    /// * `code` - Yürütülecek makine kodu baytları.
    ///
    /// VM yürütme durumu veya hatası döndürür.
    pub fn run(&mut self, code: &[u8]) -> Result<i32, ArmRuntimeError> { // Result döndürür, tamamlanma veya hata durumunu bildirir. i32 çıkış kodu için.
        println!("ARM kodunu VM belleğine yüklemeye başlanıyor...");

        // Yürütülecek kodu VM belleğine yükle.
        // ArmArchitecture içinde bellek erişim helperları olmalı (write_memory_slice).
        let code_size = code.len();
        if code_size > self.architecture.vm_memory_size {
             // Kodu yüklemek için VM belleği yeterli değil.
             eprintln!("Hata: Yüklenen kod VM belleğinden büyük (Kod boyutu: {}, Bellek boyutu: {})", code_size, self.architecture.vm_memory_size);
             return Err(ArmRuntimeError::CodeLoadError(format!("Code size ({}) exceeds VM memory size ({})", code_size, self.architecture.vm_memory_size)));
        }

        // Kodu VM belleğinin başlangıcına yaz.
        // write_memory_slice 0 adresine yazmaya çalışacaktır.
        match self.architecture.write_memory_slice(0, code) {
            Ok(_) => {
                println!("ARM kodu VM belleğine başarıyla yüklendi ({} byte).", code_size);
                // Program sayacını kodun başlangıcına ayarla (genellikle 0).
                self.architecture.set_pc(0)?; // set_pc hata dönebilir
            }
             Err(e) => {
                 // Belleğe yazma hatası (genellikle bellek sınırı dışına yazma girişimi)
                  eprintln!("Hata: Kodu VM belleğine yazarken hata oluştu: {}", e); // e Display veya Debug olmalı
                  return Err(e.into()); // ArmArchitectureError -> RuntimeError::ExecutionError
             }
        }


        println!("ARM yürütme döngüsü başlatılıyor...");

        // VM yürütme döngüsü
        // execute_next_instruction PC'deki komutu yürütür, PC'yi ilerletir ve durumu günceller.
        // Başarı döner veya bir hata (illegal instruction, bellek hatası vb.) döner.
        // Exit syscall'u özel olarak ele alınmalıdır (örneğin, execute_next_instruction'ın özel bir değer döndürmesi veya runtime'ın state'ini güncellemesi).

        loop {
            match self.architecture.execute_next_instruction() {
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
                              return Err(ArmRuntimeError::ExecutionError(ArmArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                         }
                     }
                     // Şimdilik, execute_next_instruction() sadece Result<()> dönüyor ve exit/breakpoint
                     // hatalarını ArmArchitectureError olarak döndürüyor varsayalım.
                     // Eğer Ok dönerse, döngü devam eder.

                    // Eğer ArmArchitecture::execute_next_instruction'dan Ok dönüyorsa ve bu bir exit sinyali değilse...
                    // Döngü devam eder.
                }
                Err(ArmArchitectureError::ExecutionError(msg)) if msg.starts_with("Exit with code:") => {
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
                     return Err(ArmRuntimeError::ExecutionError(ArmArchitectureError::ExecutionError(format!("Invalid exit message format: {}", msg))));
                }
                Err(ArmArchitectureError::ExecutionError(msg)) if msg == "Breakpoint reached" => {
                     println!("VM breakpoint'e ulaştı.");
                     // Breakpoint durumunda dur ve bir hata olarak bildir.
                     return Err(ArmRuntimeError::ExecutionError(ArmArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                }
                Err(e) => {
                     // execute_next_instruction'dan dönen diğer hatalar (IllegalInstruction, MemoryAccessError vb.)
                     eprintln!("ARM yürütme hatası: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                     return Err(e.into()); // ArmArchitectureError -> RuntimeError::ExecutionError
                }
            }
        }

        // Eğer döngü hiçbir zaman sonlanmazsa (exit/hata olmadan), buraya unreachable! eklenebilir
        // veya bir timeout mekanizması olabilir.
         Ok(0) // Bu satıra normalde erişilmemeli
    }

    // ARM kodu içinden çıktı almak için StandardLibrary'yi kullanan fonksiyon.
    // Bu fonksiyon runtime tarafından mimariye sağlanır ve mimari içindeki syscall/output
    // işleyicileri bu fonksiyonu çağırır.
    pub fn print(&self, s: &str) {
         // StandardLibrary'nin print_string fonksiyonu Sahne64 resource::write kullanır.
        self.standard_library.print_string(s);
    }

    // Diğer ARM çalışma zamanı fonksiyonları...
    // Örneğin: get_register, set_register, read_memory, write_memory gibi (architecture'dan çağrılarak)
    // get_pc, set_pc vb.
    // ...
}
