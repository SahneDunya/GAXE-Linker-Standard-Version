use crate::arch_loongarch::LoongarchArchitecture;
use crate::arch_loongarch::LoongarchArchitectureError; // LoongArch mimarisine özgü hata türü

// GAXE dosya formatını içe aktar (program yüklemek için)
use crate::gaxe_format::GaxeFile;

// Sahne64 hata türünü içeri aktar (Sahne64 API'sından dönebilir)
use super::SahneError; // (varsa crate::SahneError olarak değiştirin)

// Standard kütüphaneyi kullanmak için
use crate::standard_library::StandardLibrary;

// Diğer gerekli Rust core/alloc kütüphane elemanları
use alloc::string::String;
use alloc::format;
use alloc::vec::Vec; // Often needed indirectly


// LoongArch çalışma zamanı hataları için özel hata türü
#[derive(Debug)] // Hata türü için Debug trait'ini uygula
pub enum LoongarchRuntimeError {
    /// Çalışma zamanı başlatılırken Sahne64 kaynaklı bir hata oluştu.
    InitializationError(SahneError),
    /// GAXE dosyasının formatı geçersizse veya bölümler yüklenemiyorsa.
    GaxeLoadError(String),
    /// LoongArch mimarisi yürütülürken bir hata oluştu.
    ExecutionError(LoongarchArchitectureError), // String yerine LoongarchArchitectureError'ı kapsar
    /// VM'in yürütme döngüsü beklenmedik şekilde sonlandı (örn. exit komutu olmadan).
    UnexpectedTermination,
    /// VM başarılı bir şekilde yürütmeyi tamamladı (örn. exit komutu ile), çıkış kodu ile birlikte.
    ExecutionCompleted(i32), // Exit code
    // LoongarchRuntimeError'ın orijinal varyantları (ExecutionError(String), MemoryError(String), UnsupportedSystemCall(u64))
    // artık LoongarchArchitectureError içinde detaylandırılmalıdır.
    MemoryError(String) -> LoongarchArchitectureError::MemoryAccessError
    UnsupportedSystemCall(u64) -> LoongarchArchitectureError::SystemCallError (belki de alt varyantı Unsupported)
    ExecutionError(String) -> ElbrusArchitectureError::ExecutionError (daha genel mimari hata)
    // Diğer mimariye özgü hatalar LoongarchArchitectureError'a taşınmalıdır.
}

// LoongarchArchitectureError'dan LoongarchRuntimeError::ExecutionError'a dönüşüm
impl From<LoongarchArchitectureError> for LoongarchRuntimeError {
    fn from(err: LoongarchArchitectureError) -> Self {
        LoongarchRuntimeError::ExecutionError(err)
    }
}

// SahneError'dan LoongarchRuntimeError::InitializationError'a dönüşüm
// LoongarchArchitecture::new veya runtime::new içindeki diğer Sahne64 çağrıları için.
impl From<super::SahneError> for LoongarchRuntimeError { // use super::SahneError is assumed correct path
    fn from(err: super::SahneError) -> Self {
        LoongarchRuntimeError::InitializationError(err)
    }
}

impl std::error::Error for LoongarchRuntimeError {} // Implement Error trait

impl std::fmt::Display for LoongarchRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoongarchRuntimeError::InitializationError(e) => {
                write!(f, "LoongArch çalışma zamanı başlatma hatası: {:?}", e)
            }
            LoongarchRuntimeError::GaxeLoadError(msg) => {
                write!(f, "GAXE dosya yükleme hatası: {}", msg)
            }
            LoongarchRuntimeError::ExecutionError(arch_error) => {
                write!(f, "LoongArch yürütme hatası: {}", arch_error) // LoongarchArchitectureError'ın Display implementasyonunu kullanır
            }
            LoongarchRuntimeError::UnexpectedTermination => {
                write!(f, "LoongArch yürütme beklenmedik şekilde sonlandı.")
            }
            LoongarchRuntimeError::ExecutionCompleted(code) => {
                write!(f, "LoongArch yürütme başarıyla tamamlandı. Çıkış kodu: {}", code)
            }
        }
    }
}


pub struct LoongarchRuntime {
    architecture: LoongarchArchitecture,
    standard_library: StandardLibrary, // Standart kütüphane örneği
}

// Drop implementasyonu artık LoongarchArchitecture tarafından yapılmalıdır.
// impl Drop for LoongarchRuntime { ... } // Kaldırıldı

impl LoongarchRuntime {
    /// Yeni bir LoongarchRuntime örneği oluşturur ve VM belleğini tahsis eder.
    ///
    /// # Arguments
    /// * `vm_memory_size` - VM için ayrılacak bellek boyutu.
    /// * `standard_library` - VM tarafından kullanılacak StandardLibrary instance'ı.
    ///
    /// Sahne64 bellek tahsisi veya LoongarchArchitecture başlatma başarısız olursa `LoongarchRuntimeError` döner.
    pub fn new(vm_memory_size: usize, standard_library: StandardLibrary) -> Result<Self, LoongarchRuntimeError> { // Return type changed
         println!("LoongArch çalışma zamanı başlatılıyor...");

         // LoongarchArchitecture artık new fonksiyonunda bellek tahsisini yapıyor.
         // StandardLibrary'yi de LoongarchArchitecture'a geçirmeliyiz.
        let architecture = LoongarchArchitecture::new(vm_memory_size, standard_library.clone())?; // LoongarchArchitecture::new Result<Self, SahneError> döner, From implementasyonu kullanılır. StandardLibrary clone edilebilir olmalı.

         println!("LoongArch çalışma zamanı başarıyla başlatıldı.");

        Ok(LoongarchRuntime {
             architecture,
             standard_library, // StandardLibrary'nin bir kopyası architecture'da, asıl instance burada tutulur.
        })
    }

    /// GAXE dosyasından LoongArch makine kodunu ve verisini VM belleğine yükler ve yürütmeye başlar.
    ///
    /// # Arguments
    /// * `gaxe_file` - Yürütülecek programı içeren GaxeFile yapısı.
    ///
    /// VM yürütme durumu veya hatası döndürür (çıkış kodu veya hata).
    pub fn run(&mut self, gaxe_file: &GaxeFile) -> Result<i32, LoongarchRuntimeError> { // Return type changed (i32 for exit code)
        println!("LoongArch programını VM belleğine yüklemeye başlanıyor...");

        // GAXE dosyasından kod ve veri bölümlerini al
        let code = &gaxe_file.code_section.data;
        let data = &gaxe_file.data_section.data;
        let code_offset = gaxe_file.header.code_offset;
        let data_offset = gaxe_file.header.data_offset;
        let entry_point = gaxe_file.header.entry_point; // Entry point'i header'dan al

        println!("Kod bölümü boyutu: {} byte, offset: 0x{:X}", code.len(), code_offset);
        println!("Veri bölümü boyutu: {} byte, offset: 0x{:X}", data.len(), data_offset);
        println!("Giriş noktası (Entry Point): 0x{:X}", entry_point);


        // Sanal bellek boyutunu kontrol et (GAXE bölümlerini barındıracak kadar yeterli mi?)
        let required_size = (code_offset + code.len() as u64).max(data_offset + data.len() as u64) as usize;
        if required_size > self.architecture.vm_memory_size {
             eprintln!("Hata: Yüklenen bölümler VM belleğinden büyük (Gerekli boyut: {}, Bellek boyutu: {})", required_size, self.architecture.vm_memory_size);
             return Err(LoongarchRuntimeError::GaxeLoadError(format!("Required memory size ({}) exceeds VM memory size ({})", required_size, self.architecture.vm_memory_size)));
        }

        // Kod bölümünü belleğe yükle (Architecture'ın helper'ını kullan)
        match self.architecture.write_memory_slice(code_offset, code) { // write_memory_slice should be in architecture
             Ok(_) => println!("Kod bölümü belleğe yüklendi (0x{:X} adresine).", code_offset),
             Err(e) => {
                 eprintln!("Hata: Kod bölümünü VM belleğine yazarken hata oluştu: {:?}", e);
                 return Err(e.into()); // LoongarchArchitectureError -> RuntimeError::ExecutionError
             }
        }

        // Veri bölümünü belleğe yükle (Architecture'ın helper'ını kullan)
        match self.architecture.write_memory_slice(data_offset, data) { // write_memory_slice should be in architecture
             Ok(_) => println!("Veri bölümü belleğe yüklendi (0x{:X} adresine).", data_offset),
             Err(e) => {
                 eprintln!("Hata: Veri bölümünü VM belleğine yazarken hata oluştu: {:?}", e);
                 return Err(e.into()); // LoongarchArchitectureError -> RuntimeError::ExecutionError
             }
        }


        // Program sayacını giriş noktasına ayarla
        self.architecture.set_pc(entry_point)?; // set_pc should be in architecture

        println!("LoongArch yürütme döngüsü başlatılıyor...");

        // VM yürütme döngüsü
        // execute_next_instruction PC'deki komutu yürütür, PC'yi ilerletir ve durumu günceller.
        // Başarı döner veya bir hata (illegal instruction, bellek hatası vb.) döner.
        // Exit syscall'u veya komutu özel olarak ele alınmalıdır (architecture tarafından sinyal verilir).

        loop {
            // LoongarchArchitecture::execute_instruction(code) çağrısı kaldırıldı.
            // Yerine LoongarchArchitecture::execute_next_instruction() çağrılacak.
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
                              return Err(LoongarchRuntimeError::ExecutionError(LoongarchArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                         }
                     }
                     // Şimdilik, execute_next_instruction() sadece Result<()> dönüyor ve exit/breakpoint
                     // hatalarını LoongarchArchitectureError olarak döndürüyor varsayalım (ARM runtime örneğindeki gibi).
                     // Eğer Ok dönerse, döngü devam eder.

                    // Eğer LoongarchArchitecture::execute_next_instruction'dan Ok dönüyorsa ve bu bir exit sinyali değilse...
                    // Döngü devam eder.
                }
                // LoongarchArchitectureError içinden Exit veya Breakpoint gibi özel durumları yakala
                 Err(LoongarchArchitectureError::ExecutionError(msg)) if msg.starts_with("Exit with code:") => {
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
                     return Err(LoongarchRuntimeError::ExecutionError(LoongarchArchitectureError::ExecutionError(format!("Invalid exit message format: {}", msg))));
                }
                Err(LoongarchArchitectureError::ExecutionError(msg)) if msg == "Breakpoint reached" => {
                     println!("VM breakpoint'e ulaştı.");
                     // Breakpoint durumunda dur ve bir hata olarak bildir.
                     return Err(LoongarchRuntimeError::ExecutionError(LoongarchArchitectureError::ExecutionError("Breakpoint reached".to_string())));
                }
                 Err(e) => {
                     // execute_next_instruction'dan dönen diğer hatalar (IllegalInstruction, MemoryAccessError, SystemCallError vb.)
                     eprintln!("LoongArch yürütme hatası: {:?}", e); // e'nin Debug veya Display implementasyonu olmalı
                     return Err(e.into()); // LoongarchArchitectureError -> RuntimeError::ExecutionError
                }
            }
        }

        // Eğer döngü hiçbir zaman sonlanmazsa (exit/hata olmadan), buraya unreachable! eklenebilir
        // veya bir timeout mekanizması olabilir.
         Ok(0) // Bu satıra normalde erişilmemeli
    }

    // Diğer LoongArch çalışma zamanı fonksiyonları... (gerektiğinde eklenebilir)
    // Örneğin: get_register, set_register, read_memory, write_memory gibi (architecture'dan çağrılarak)
    // get_pc (architecture'dan)
    // ...
}
