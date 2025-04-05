use crate::arch_x86::X86Architecture;
use super::memory; // Sahne64 bellek yönetimi için
use super::fs;     // Sahne64 dosya sistemi (I/O için)
use super::SahneError; // Sahne64 hata türü

pub struct X86Runtime {
    architecture: X86Architecture,
    // Çalışma zamanına özgü diğer durumlar buraya eklenebilir.
    // Örneğin: Registerlar, Bellek, Hata durumları, vb.
    memory: Option<*mut u8>, // Sanal x86 belleği için bir işaretçi
    memory_size: usize,      // Sanal x86 belleğinin boyutu
}

impl X86Runtime {
    /// Yeni bir X86Runtime örneği oluşturur.
    pub fn new(memory_size: usize) -> Self {
        X86Runtime {
            architecture: X86Architecture::new(), // X86Architecture'ı başlatmayı unutmayın
            memory: None,
            memory_size,
        }
    }

    /// Sanal x86 belleğini Sahne64 üzerinden ayırır.
    pub fn initialize_memory(&mut self) -> Result<(), SahneError> {
        match memory::allocate(self.memory_size) {
            Ok(ptr) => {
                self.memory = Some(ptr);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Sanal x86 belleğini serbest bırakır.
    pub fn deallocate_memory(&mut self) {
        if let Some(ptr) = self.memory {
            let _ = memory::free(ptr, self.memory_size); // Hata durumunu şimdilik göz ardı ediyoruz
            self.memory = None;
            self.memory_size = 0;
        }
    }

    /// Verilen x86 byte kodunu yürütür.
    ///
    /// # Arguments
    ///
    /// * `code` - Yürütülecek x86 byte kodu.
    ///
    /// # Returns
    ///
    /// * `Result<(), String>` - Yürütme başarılı olursa `Ok(())`, hata durumunda `Err(String)` döner.
    ///
    /// # Errors
    ///
    /// Bu fonksiyon, x86 kodunun yürütülmesi sırasında bir hata oluşursa `Err` dönebilir.
    /// Hata mesajı, hatanın nedenini açıklayan bir `String` olacaktır.
    pub fn run(&self, code: &[u8]) -> Result<(), String> {
        println!("X86 kodu çalışma zamanı başlatılıyor...");

        // Sanal x86 belleğini kullanıma hazır hale getir (eğer ayrılmışsa)
        if self.memory.is_some() {
            println!("Sanal x86 belleği ayrıldı: {} byte", self.memory_size);
            // Belleği başlangıç değerleriyle doldurma veya başka hazırlık işlemleri yapılabilir.
        } else {
            println!("Uyarı: Sanal x86 belleği ayrılmamış.");
        }

        // x86 kodunu yürütme mantığı
        // Bu kısımda, self.memory içindeki sanal belleğe erişim ve değişiklik yapılması gerekebilir.
        let execution_result = self.architecture.execute_instruction(code);

        match execution_result {
            Ok(_) => {
                println!("X86 kodu başarıyla yürütüldü.");
                Ok(()) // Başarılı yürütme
            }
            Err(error_message) => {
                eprintln!("X86 kodu yürütülürken hata oluştu: {}", error_message);
                Err(error_message) // Hata durumunda hatayı döndür
            }
        }
    }

    // Diğer x86 çalışma zamanı fonksiyonları buraya eklenebilir.
    // Örneğin:
    // - Register değerlerini okuma/yazma fonksiyonları (bu, X86Architecture içinde olabilir)
    // - Bellek yönetimi fonksiyonları (yukarıda temel allocate/free eklendi)
    // - Sistem çağrıları işleme fonksiyonları (Sahne64'ün syscall'lerini kullanabilir)
    // - Girdi/çıktı işlemleri (Sahne64'ün fs modülünü kullanabilir)
    // - Hata ayıklama (debugging) fonksiyonları
}