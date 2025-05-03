use crate::resource;
use crate::SahneError; // Sahne64 hata türü
use crate::Handle; // Sahne64 kaynak tanıtıcısı

use alloc::string::String; // String kullanıldığı için
use alloc::vec::Vec; // Vec kullanıldığı için
use alloc::format; // format! makrosu kullanıldığı için
use core::fmt; // Error Display için

pub struct LoongarchAssembler;

// LoongArch Assembler özel hata türleri
#[derive(Debug)] // fmt::Display de burada derive edilebilir
pub enum AssemblerError {
    SyntaxError(String),
    UnsupportedInstruction(String), // Gerçek assembler'da komut detayını içerebilir
    UndefinedSymbol(String), // Eğer etiket/sembol desteği eklenirse
    EncodingError(String), // Dosya okuma/yazma sırasında kodlama hatası
    IOError(SahneError), // Sahne64 kaynaklı IO hataları
    // Diğer olası derleyici hataları...
}

// SahneError'dan AssemblerError'a dönüşüm
impl From<SahneError> for AssemblerError {
    fn from(err: SahneError) -> Self {
        AssemblerError::IOError(err)
    }
}

// Hata türünü yazdırılabilir yapmak için Display implementasyonu
impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssemblerError::SyntaxError(msg) => write!(f, "Sözdizimi Hatası: {}", msg),
            AssemblerError::UnsupportedInstruction(instr) => write!(f, "Desteklenmeyen Komut: {}", instr),
            AssemblerError::UndefinedSymbol(symbol) => write!(f, "Tanımsız Sembol: {}", symbol),
            AssemblerError::EncodingError(msg) => write!(f, "Kodlama Hatası: {}", msg),
            AssemblerError::IOError(e) => write!(f, "IO Hatası: {:?}", e), // SahneError'ın Debug çıktısını kullan
        }
    }
}

// std::error::Error trait implementasyonu no_std ortamında std feature gerektirir.
// Eğer std feature yoksa bu kısım koşullu derlenmelidir.
 #[cfg(feature = "std")]
 impl std::error::Error for AssemblerError {}


impl LoongarchAssembler {
    pub fn new() -> Self {
        LoongarchAssembler {
            // Sembol tablosu gibi durumlar buraya eklenebilir:
             label_addresses: alloc::collections::HashMap::new(),
        }
    }

    /// Verilen dosyadaki LoongArch assembly kodunu okur ve derler.
    /// Sahne64 resource modülünü dosya okuma için kullanır.
    pub fn assemble_from_file(&self, input_filename: &str) -> Result<Vec<u8>, AssemblerError> { // Return type changed
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // fs::O_RDONLY yerine resource::MODE_READ kullan
        match resource::acquire(input_filename, resource::MODE_READ) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024]; // Okuma için ara bellek

                // Sahne64 resource::read kullanarak dosyadan oku
                // fs::read(fd, &mut chunk) yerine resource::read(file_handle, &mut chunk) kullan
                loop {
                    match resource::read(file_handle, &mut chunk) {
                        Ok(bytes_read) => {
                            if bytes_read == 0 { // Dosya sonuna gelindi
                                break;
                            }
                            buffer.extend_from_slice(&chunk[..bytes_read]);
                        }
                        Err(e) => {
                            // Hata oluşursa dosyayı kapat (release) ve hatayı propagate et
                            let _ = resource::release(file_handle); // Dosyayı kapatmaya çalış
                            // SahneError'ı AssemblerError'a çevir
                            return Err(e.into());
                        }
                    }
                }

                // Dosya okuma bitti, dosyayı kapat (release)
                // fs::close(fd) yerine resource::release(file_handle) kullan
                if let Err(e) = resource::release(file_handle) {
                    eprintln!("Dosya kapatma hatası (okuma): {:?}", e);
                     // Kapatma hatası da döndürülebilir, şu an sadece loglaniyor
                      return Err(e.into());
                }

                // Okunan byte'ları UTF-8 string'e çevir
                match String::from_utf8(buffer) {
                    Ok(assembly_code) => {
                         // self.assemble_code AssemblerError döndürecek şekilde güncellendi
                         self.assemble_code(&assembly_code) // Asıl derleme işlevini çağır
                    }
                     // UTF-8 hatasını AssemblerError::EncodingError'a çevir
                    Err(e) => Err(AssemblerError::EncodingError(format!("Dosya içeriği geçerli UTF-8 değil: {}", e))),
                }
            }
            // Dosya açma hatasını propagate et (SahneError -> AssemblerError)
            Err(e) => Err(e.into()),
        }
    }

    /// Üretilen makine kodunu bir dosyaya yazar.
    /// Sahne64 resource modülünü dosya yazma için kullanır.
    pub fn write_machine_code_to_file(&self, output_filename: &str, machine_code: &[u8]) -> Result<(), AssemblerError> { // Return type changed
        // Sahne64 resource modülünü kullanarak dosyayı aç (acquire)
        // fs::open yerine resource::acquire kullan
        // Bayrakları güncelle: fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC
        // resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE kullan
        match resource::acquire(output_filename, resource::MODE_WRITE | resource::MODE_CREATE | resource::MODE_TRUNCATE) {
            Ok(file_handle) => { // fd (u64) yerine Handle kullan
                // Sahne64 resource::write kullanarak dosyaya yaz
                /// fs::write(fd, machine_code) yerine resource::write(file_handle, machine_code) kullan
                match resource::write(file_handle, machine_code) {
                    Ok(bytes_written) => {
                         let close_result = resource::release(file_handle); // Dosyayı kapat

                         if bytes_written as usize != machine_code.len() {
                             // Yazılan byte sayısı beklenenle uyuşmuyorsa hata
                              eprintln!("Uyarı: Tüm makine kodu dosyaya yazılamadı. Yazılan: {}, Beklenen: {}", bytes_written, machine_code.len());
                              // Kapatma hatası olsa bile yazma hatasını döndür
                               if let Err(e) = close_result {
                                   eprintln!("Dosya kapatma hatası (yazma sonrası uyarıda): {:?}", e);
                                   // Kapatma hatası önemliyse burada da dönebilirsiniz
                              }
                               return Err(AssemblerError::IOError(SahneError::CommunicationError)); // Veya daha iyi bir hata
                         }

                         // Yazma başarılı, kapatma hatasını kontrol et
                         if let Err(e) = close_result {
                            eprintln!("Dosya kapatma hatası (yazma): {:?}", e);
                             // Kapatma hatasını döndürmek isteyebilirsiniz
                             return Err(e.into()); // SahneError'ı AssemblerError'a çevir
                         }

                        Ok(()) // Yazma ve kapatma başarılı
                    }
                    Err(e) => {
                        // Yazma hatası oluşursa dosyayı kapat (release) ve hatayı propagate et
                        let _ = resource::release(file_handle); // Dosyayı kapatmaya çalış
                        Err(e.into()) // SahneError'ı AssemblerError'a çevir
                    }
                }
            }
            // Dosya açma hatasını propagate et (SahneError -> AssemblerError)
            Err(e) => Err(e.into()),
        }
    }

    /// Verilen LoongArch assembly kodunu makine koduna çevirir (temel işlev).
    /// Gerçek derleyici mantığı buraya yazılmalıdır.
    /// Sözdizimi hataları vb. için Result döndürür.
    pub fn assemble_code(&self, assembly_code: &str) -> Result<Vec<u8>, AssemblerError> { // Return type changed
        if assembly_code.is_empty() {
            println!("Uyarı: Assembly kodu boş. Boş bir çıktı üretiliyor.");
            return Ok(Vec::new()); // Başarılı boş sonuç dön
        }

        println!("LoongArch assembly kodu derleniyor (basit örnek)...");
        // **DİKKAT:** Bu kısım GERÇEK LoongArch assembly'e çeviri yapmaz.
        // Gerçek derleyici mantığı (parsing, semantik analiz, kod üretimi) buraya yazılmalıdır.
        // Bu süreçte sözdizimi, bilinmeyen komut, yanlış argüman vb. hatalar
        // AssemblerError'ın diğer varyantları olarak döndürülmelidir.

        // Örnek olarak sadece girilen stringi byte dizisine çeviriyor (YANLIŞ MAKİNE KODU ÜRETİR!)
        let machine_code = assembly_code.as_bytes().to_vec();

        println!("LoongArch assembly derlemesi tamamlandı (basit örnek). Simüle edilen makine kodu boyutu: {} bayt.", machine_code.len());

        // Gerçek bir derleyici burada oluşabilecek hataları kontrol ederdi.
        return Err(AssemblerError::SyntaxError("Beklenmeyen token".to_string()));

        Ok(machine_code) // Başarılı sonuç dön
    }

    // Diğer LoongArch assembly işleme fonksiyonları...
    // Örneğin: sembol tablosu, ikinci geçiş (adres çözümleme), data section işleme, VLIW şablonlama vb.
}
