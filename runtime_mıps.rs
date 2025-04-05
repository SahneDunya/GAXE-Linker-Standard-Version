use crate::arch_mips::MipsArchitecture;
use crate::standard_library::StandardLibrary; // Standart kütüphaneyi kullanmak için
use super::memory; // Sahne64 bellek yönetimi için
use super::SahneError;
use std::error::Error;
use std::fmt;

// Özel hata türü tanımla
#[derive(Debug, fmt::Display)]
pub enum MipsRuntimeError {
    ExecutionError(String), // Yürütme sırasında oluşan hatalar için
    InitializationError(String), // Başlatma sırasında oluşan hatalar için
    UnsupportedOperation(String), // Desteklenmeyen işlemler için
    MemoryError(SahneError), // Sahne64 bellek hataları için
    // ... diğer hata türleri ...
}

impl From<SahneError> for MipsRuntimeError {
    fn from(err: SahneError) -> Self {
        MipsRuntimeError::MemoryError(err)
    }
}

impl std::error::Error for MipsRuntimeError {}

pub struct MipsRuntime {
    architecture: MipsArchitecture,
    // Çalışma zamanı için ek durumlar buraya gelebilir
    // Örneğin: registerlar, bellek, program sayacı vb.
    // registers: HashMap<String, u32>,
    memory_start: *mut u8, // Sahne64 tarafından yönetilen bellek bloğunun başlangıç adresi
    memory_size: usize,    // Bellek bloğunun boyutu
    // pc: u32,
    standard_library: StandardLibrary, // Standart kütüphane örneği
}

impl MipsRuntime {
    pub fn new(architecture: Architecture) -> Result<Self, MipsRuntimeError> {
        println!("MIPS Çalışma Zamanı Başlatılıyor...");
        let mips_arch = MipsArchitecture::new(); // MipsArchitecture::new() eklendi, eğer varsa

        // Sahne64 bellek yönetimini kullanarak bir bellek bloğu ayır
        let memory_size = 4096; // Örnek bellek boyutu (4KB)
        let memory_start = memory::allocate(memory_size)?;

        let standard_library = StandardLibrary::new(architecture);

        // Çalışma zamanı durumunu başlat...
        // Örn: registerları sıfırla, belleği ayır vb.
        // ...

        println!("MIPS Çalışma Zamanı Başarıyla Başlatıldı. Bellek boyutu: {} byte", memory_size);
        Ok(MipsRuntime {
            architecture: mips_arch,
            memory_start,
            memory_size,
            standard_library,
            // registers: HashMap::new(),
            // pc: 0,
        })
    }

    pub fn run(&mut self, code: &[u8]) -> Result<(), MipsRuntimeError> {
        println!("MIPS kodu yürütülmeye başlanıyor...");

        // Kod yürütme mantığı
        // **BURADA GERÇEK MIPS YÜRÜTME MANTIĞI OLACAK**
        // Bu örnekte, MIPS mimarisine özgü yürütme detayları (fetch, decode, execute döngüsü, register yönetimi, bellek erişimi vb.)
        // MipsArchitecture struct'ı içinde veya burada implemente edilmelidir.

        // Örnek olarak, standart kütüphaneyi kullanarak bir çıktı alalım:
        self.standard_library.print_string("MIPS Çalışma Zamanından Merhaba!");

        let result = self.architecture.execute_instruction(code); // execute_instruction'ın Result döndürdüğünü varsayıyoruz

        match result {
            Ok(_) => {
                println!("MIPS kodu başarıyla yürütüldü.");
                Ok(()) // Başarılı yürütme
            }
            Err(e) => {
                eprintln!("MIPS kodu yürütülürken hata oluştu: {}", e);
                Err(MipsRuntimeError::ExecutionError(format!("Yürütme hatası: {}", e))) // Hatayı MipsRuntimeError'a dönüştür
            }
        }
    }

    // Bellek okuma fonksiyonu (Sahne64 tarafından yönetilen belleği kullanır)
    pub fn read_memory(&self, address: u32, size: usize) -> Result<Vec<u8>, MipsRuntimeError> {
        if address as usize + size > self.memory_size {
            return Err(MipsRuntimeError::ExecutionError("Bellek sınırları aşıldı".to_string()));
        }
        let ptr = unsafe { self.memory_start.add(address as usize) };
        let slice = unsafe { core::slice::from_raw_parts(ptr, size) };
        Ok(slice.to_vec())
    }

    // Bellek yazma fonksiyonu (Sahne64 tarafından yönetilen belleği kullanır)
    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MipsRuntimeError> {
        if address as usize + data.len() > self.memory_size {
            return Err(MipsRuntimeError::ExecutionError("Bellek sınırları aşıldı".to_string()));
        }
        let ptr = unsafe { self.memory_start.add(address as usize) };
        let dest = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, data.len()) };
        dest.copy_from_slice(data);
        Ok(())
    }

    // Diğer MIPS çalışma zamanı fonksiyonları... (gerektiğinde eklenebilir)
    // Örn: register erişimi, sistem çağrıları vb.
}