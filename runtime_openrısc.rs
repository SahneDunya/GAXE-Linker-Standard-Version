use crate::arch_openrisc::OpenriscArchitecture;
use crate::standard_library::StandardLibrary; // Standart kütüphaneyi içeri aktar
use super::memory; // Sahne64 bellek yönetimini içeri aktar
use super::SahneError; // Sahne64 hatalarını içeri aktar
use std::fmt;

#[derive(Debug, fmt::Display)]
pub enum OpenriscRuntimeError {
    ExecutionError(String), // Genel yürütme hataları için
    MemoryError(SahneError), // Sahne64 bellek hataları için
    IOError(SahneError),     // Sahne64 I/O hataları için
    // Gerekirse buraya daha özel hata türleri eklenebilir.
}

impl From<SahneError> for OpenriscRuntimeError {
    fn from(err: SahneError) -> Self {
        match err {
            SahneError::MemoryError(_) => OpenriscRuntimeError::MemoryError(err),
            _ => OpenriscRuntimeError::IOError(err), // Diğer Sahne hatalarını I/O hatası olarak kabul edelim şimdilik
        }
    }
}

impl std::error::Error for OpenriscRuntimeError {}

pub struct OpenriscRuntime {
    architecture: OpenriscArchitecture,
    standard_library: StandardLibrary, // Standart kütüphane örneği
    memory_start: Option<*mut u8>,   // Sahne64 tarafından yönetilen bellek bloğunun başlangıcı
    memory_size: usize,             // Yönetilen bellek bloğunun boyutu
    // Çalışma zamanı durumu için diğer alanlar buraya eklenebilir, örneğin registerlar vb.
    // registers: ...
}

impl OpenriscRuntime {
    pub fn new() -> Self {
        println!("OpenRISC Runtime başlatılıyor...");
        OpenriscRuntime {
            architecture: OpenriscArchitecture::new(),
            standard_library: StandardLibrary::new(Architecture::OpenRISC), // Standart kütüphaneyi başlat
            memory_start: None,
            memory_size: 0,
            // registers: ...
        }
    }

    // Sahne64 bellek yönetimini kullanarak bellek ayırma
    pub fn initialize_memory(&mut self, size: usize) -> Result<(), OpenriscRuntimeError> {
        match memory::allocate(size) {
            Ok(ptr) => {
                self.memory_start = Some(ptr);
                self.memory_size = size;
                println!("OpenRISC için {} byte bellek ayrıldı.", size);
                Ok(())
            }
            Err(e) => Err(OpenriscRuntimeError::MemoryError(e)),
        }
    }

    // Belleğe yazma (örnek)
    pub fn write_memory(&self, address: u32, data: &[u8]) -> Result<(), OpenriscRuntimeError> {
        match self.memory_start {
            Some(start) => {
                if (address as usize) < self.memory_size && (address as usize + data.len()) <= self.memory_size {
                    let ptr = unsafe { start.add(address as usize) };
                    let dest = unsafe { core::slice::from_raw_parts_mut(ptr, data.len()) };
                    dest.copy_from_slice(data);
                    Ok(())
                } else {
                    Err(OpenriscRuntimeError::ExecutionError("Geçersiz bellek adresi veya boyutu.".to_string()))
                }
            }
            None => Err(OpenriscRuntimeError::ExecutionError("Bellek henüz başlatılmadı.".to_string())),
        }
    }

    // Bellekten okuma (örnek)
    pub fn read_memory(&self, address: u32, size: usize) -> Result<&[u8], OpenriscRuntimeError> {
        match self.memory_start {
            Some(start) => {
                if (address as usize) < self.memory_size && (address as usize + size) <= self.memory_size {
                    let ptr = unsafe { start.add(address as usize) };
                    let slice = unsafe { core::slice::from_raw_parts(ptr, size) };
                    Ok(slice)
                } else {
                    Err(OpenriscRuntimeError::ExecutionError("Geçersiz bellek adresi veya boyutu.".to_string()))
                }
            }
            None => Err(OpenriscRuntimeError::ExecutionError("Bellek henüz başlatılmadı.".to_string())),
        }
    }

    pub fn run(&self, code: &[u8]) -> Result<(), OpenriscRuntimeError> {
        println!("OpenRISC kod yürütmesi başlatılıyor. Kod boyutu: {} byte", code.len());

        if code.is_empty() {
            return Err(OpenriscRuntimeError::ExecutionError("Yürütülecek kod yok.".to_string()));
        }

        // **ÖNEMLİ:** OpenRISC mimarisinin çıktı (örneğin, konsola yazdırma) işlemleri nasıl ele alınacak?
        // Genellikle bu, belirli bir bellek adresine yazarak veya bir sistem çağrısı yaparak gerçekleşir.
        // Bu noktada, OpenriscArchitecture'ın bu işlemleri nasıl simüle ettiğini bilmemiz gerekiyor.

        // **Örnek Yaklaşım:** Eğer OpenRISC kodu belirli bir adrese (örneğin, 0x80000000) bir string yazarsa,
        // biz bu adresi kontrol edip StandardLibrary'yi kullanarak çıktıyı alabiliriz.

        // **Daha Gelişmiş Yaklaşım:** OpenRISC için bir sistem çağrı mekanizması simüle edilebilir ve
        // bu mekanizma Sahne64'ün sistem çağrılarına (örneğin, çıktı için fs::write) yönlendirilebilir.

        // Şimdilik basit bir örnek olarak, kodun yürütülmesinin başarılı olduğunu varsayalım ve
        // bir çıktı işlemi yapıldığında StandardLibrary'yi nasıl kullanabileceğimizi gösterelim.

        // **Yer Tutucu: OpenRISC kodu tarafından bir çıktı stringi oluşturulduğunu varsayalım.**
        let output_string = "OpenRISC uygulamasından merhaba!";

        // Bu çıktıyı Sahne64'ün standart çıktısına yönlendirelim:
        self.standard_library.print_string(output_string);

        match self.architecture.execute_instruction(code) {
            Ok(_) => {
                println!("OpenRISC kod yürütmesi başarıyla tamamlandı.");
                Ok(())
            }
            Err(arch_error) => {
                let error_message = format!("OpenRISC mimari hatası: {}", arch_error);
                eprintln!("HATA: {}", error_message);
                Err(OpenriscRuntimeError::ExecutionError(error_message))
            }
        }
    }

    // Diğer çalışma zamanı fonksiyonları eklenebilir.
}