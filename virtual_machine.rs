use crate::gaxe_format::{Architecture, GaxeFile}; // gaxe_format.rs'den içe aktarın
use crate::standard_library::StandardLibrary; // standart_library.rs'den içe aktarın
use std::fmt;

#[derive(Debug, fmt::Display)]
pub enum VMError {
    UnsupportedArchitecture(Architecture),
    // Diğer VM hataları buraya eklenebilir
    IOError(super::SahneError), // SahneError'ı VMError'a dahil et
}

impl From<super::SahneError> for VMError {
    fn from(err: super::SahneError) -> Self {
        VMError::IOError(err)
    }
}

impl std::error::Error for VMError {}

pub struct VirtualMachine {
    gaxe_file: GaxeFile,
    standard_library: StandardLibrary, // Standart kütüphane örneği
    // VM durumu için alanlar buraya eklenebilir, örneğin:
    // registers: HashMap<String, u64>,
    // memory: Vec<u8>,
    // ...
}

impl VirtualMachine {
    pub fn new(gaxe_file: GaxeFile) -> Self {
        let architecture = gaxe_file.header.architecture;
        VirtualMachine {
            gaxe_file,
            standard_library: StandardLibrary::new(architecture), // Standart kütüphaneyi başlat
            // VM durumunu başlat...
            // registers: HashMap::new(),
            // memory: vec![0; 1024], // Örneğin 1KB bellek
            // ...
        }
    }

    pub fn run(&mut self) -> Result<(), VMError> {
        println!("GAXE dosyasını yürütülüyor. Mimari: {:?}", self.gaxe_file.header.architecture);
        match self.gaxe_file.header.architecture {
            Architecture::X86 => self.run_architecture("x86"),
            Architecture::ARM => self.run_architecture("ARM"),
            Architecture::RISCV => self.run_architecture("RISC-V"),
            Architecture::OpenRISC => self.run_architecture("OpenRISC"),
            Architecture::LoongArch => self.run_architecture("LoongArch"),
            Architecture::Elbrus => self.run_architecture("Elbrus"),
            Architecture::MIPS => self.run_architecture("MIPS"),
            Architecture::SPARC => self.run_architecture("SPARC"),
            Architecture::PowerPC => self.run_architecture("PowerPC"),
            _ => Err(VMError::UnsupportedArchitecture(self.gaxe_file.header.architecture))?, // Desteklenmeyen mimariler için hata döndür
        }
        Ok(()) // Şimdilik her mimari için başarılı dönüş
    }

    // Ortak yürütme fonksiyonu, mimariye özel mantık eklenebilir
    fn run_architecture(&mut self, arch_name: &str) {
        println!("{} mimarisi için kod yürütülüyor...", arch_name);
        // Mimariye özgü yürütme mantığı buraya eklenecek.
        // Örneğin, opcode'ları ayrıştırma ve yürütme, registerları ve belleği yönetme, vb.
        // Şu anda sadece bir yer tutucu mesajı yazdırıyoruz ve standart kütüphaneyi kullanma örneği gösteriyoruz.

        // Kod bölümüne erişim:
        let code = &self.gaxe_file.code_section.data;
        println!("Kod bölümü boyutu: {} byte", code.len());
        // Veri bölümüne erişim:
        let data = &self.gaxe_file.data_section.data;
        println!("Veri bölümü boyutu: {} byte", data.len());

        // **Örnek:** Sanal makine içinde bir string oluşturulduğunu ve standart kütüphane ile yazdırıldığını varsayalım.
        let message = format!("[{}] GAXE uygulamasından merhaba!", arch_name);
        self.standard_library.print_string(&message);

        // **GERÇEK VM MANTIĞI BURAYA GELECEK**
        // Burada, 'code' byte dizisindeki makine kodunu yorumlayacak veya çalıştıracak bir döngü ve mantık olmalıdır.
        // Bu, her mimari için farklı olacaktır. Sanal registerlar, bellek yönetimi, I/O işlemleri vb. burada simüle edilmelidir.
        // Eğer yürütülen kod bir çıktı işlemi yapmak isterse, bu, 'standard_library.print_string' fonksiyonunu çağırmak şeklinde olabilir.

        println!("{} mimarisi için kod yürütme tamamlandı.", arch_name);
    }
}