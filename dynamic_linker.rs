// dynamic_linker.rs
#![no_std]

use crate::linker_config::LinkerConfig;
use crate::object_parser::{ObjectFile, ElfSection, ElfSymbol, ElfRelocation, SHT_DYNSYM, SHT_STRTAB, SHT_PROGBITS, SHT_RELA, STB_GLOBAL, STT_FUNC, STT_OBJECT, SHN_UNDEF};
use crate::symbol_resolver::{SymbolResolver, ResolvedSymbol};
use crate::error::{LinkerError, Result, DynamicLinkerError};
use sahne64::utils::{String, Vec, HashMap};
use sahne64::{print, println, eprintln};

// ELF Dinamik Etiketler (DT_*)
// Kaynak: https://refspecs.linuxfoundation.org/elf/gabi-elf.html#dynamic_section
const DT_NULL: u64 = 0;           // End of dynamic section
const DT_NEEDED: u64 = 1;         // Name of needed library
const DT_PLTRELSZ: u64 = 2;       // Size of PLT relocation entries
const DT_PLTGOT: u64 = 3;         // Address of PLT/GOT
const DT_HASH: u64 = 4;           // Address of symbol hash table
const DT_STRTAB: u64 = 5;         // Address of string table
const DT_SYMTAB: u64 = 6;         // Address of symbol table
const DT_RELA: u64 = 7;           // Address of relocation table (with addends)
const DT_RELASZ: u64 = 8;         // Size of relocation table (with addends)
const DT_RELAENT: u64 = 9;        // Size of relocation entry (with addends)
const DT_STRSZ: u64 = 10;         // Size of string table
const DT_SYMENT: u64 = 11;        // Size of symbol table entry
const DT_INIT: u64 = 12;          // Address of initialization function
const DT_FINI: u64 = 13;          // Address of termination function
const DT_SONAME: u64 = 14;        // Shared object name
const DT_RPATH: u64 = 15;         // Library search path
const DT_SYMBOLIC: u64 = 16;      // Statically linked
const DT_REL: u64 = 17;           // Address of relocation table (no addends)
const DT_RELSZ: u64 = 18;         // Size of relocation table (no addends)
const DT_RELENT: u64 = 19;        // Size of relocation entry (no addends)
const DT_PLTREL: u64 = 20;        // Type of relocations in PLT
const DT_DEBUG: u64 = 21;         // Debugging entry
const DT_TEXTREL: u64 = 22;       // Relocations in text segment allowed
const DT_JMPREL: u64 = 23;        // Address of PLT relocations

// Relocation Tipleri (Dinamik Bağlama ile ilgili)
const R_X86_64_JUMP_SLOT: u32 = 7; // For PLT entries (x86_64)
const R_X86_64_GLOB_DAT: u32 = 6;  // For GOT entries (x86_64)
// AArch64 ve RISC-V için benzer JUMP_SLOT/GLOB_DAT tipleri vardır.
// Örnek: R_AARCH64_JUMP_SLOT (263), R_AARCH64_GLOB_DAT (264)
// Örnek: R_RISCV_JUMP_SLOT (20), R_RISCV_GLOB_DAT (19)

/// Dinamik bağlama için gerekli bilgileri içeren Dynamic Segment Entry.
#[derive(Debug, Clone)]
pub struct DynamicEntry {
    pub tag: u64, // DT_* değeri
    pub val: u64, // İlgili değer (adres, boyut, offset)
}

/// Çalışma zamanı dinamik bağlamayı hazırlayan yapı.
/// Bu yapı, statik linker'ın çıktısında, dinamik linker'ın
/// çalışma zamanında kullanacağı bilgileri yerleştirir.
pub struct DynamicLinker {
    // Statik linker tarafından oluşturulmuş resolved_symbols_map
    // Çalışma zamanı dinamik linker'ı için bu harita önemli değil,
    // ancak burada, statik linker'ın bu bilgilere ihtiyacı olduğu için tutulur.
    // Örneğin, hangi sembollerin dışa aktarılması gerektiği.
    // pub resolved_symbols: HashMap<String, ResolvedSymbol>, // Artık SymbolResolver'dan direkt alınacak.
    // Dinamik olarak yüklenmesi gereken kütüphaneler
    pub needed_libraries: Vec<String>,
}

impl DynamicLinker {
    pub fn new() -> Self {
        DynamicLinker {
             resolved_symbols: HashMap::new(),
            needed_libraries: Vec::new(),
        }
    }

    /// Dinamik bağlama için gerekli yapıları (GOT, PLT, .dynamic bölümü) hazırlar.
    /// Bu fonksiyon, esasen **statik linker'ın dinamik bir yürütülebilir dosya üretirken**
    /// yapması gereken işleri içerir.
    pub fn prepare_dynamic_linking(
        &mut self,
        object_files: &mut Vec<ObjectFile>,
        config: &LinkerConfig,
        symbol_resolver: &mut SymbolResolver, // SymbolResolver'dan güncel verileri almak için
        // object_files'ın nihai segment adresleri bilgisi
        // Bu bilgi Relocator veya ayrı bir Layout fazından gelmelidir.
        // Şimdilik basitleştirilmiş bir adresleme kullanacağız.
    ) -> Result<()> {
        println!("INFO: Dinamik bağlama yapılandırması hazırlanıyor...");

        if !config.enable_dynamic_linking {
            println!("INFO: Dinamik bağlama devre dışı bırakıldı. İşlem atlanıyor.");
            return Ok(());
        }

        // 1. Gerekli Kütüphaneleri Topla (DT_NEEDED)
        // Genellikle, .o dosyalarında doğrudan DT_NEEDED bulunmaz.
        // Bunlar daha çok paylaşılan kütüphanelerde (.so) veya linker'ın kendisi tarafından eklenir.
        // Varsayalım ki config'de veya başka bir yerden DT_NEEDED listesi geliyor.
        // Şu anki yapılandırmada DT_NEEDED yoktur, ancak gelecekte `linker_config.rs`'ye eklenebilir.
        // Bu örnek için elle ekleyelim.
         self.needed_libraries.push(String::from_str("libc.so"));
         self.needed_libraries.push(String::from_str("libm.so"));

        // 2. `.dynsym` (Dynamic Symbol Table) ve `.dynstr` (Dynamic String Table) Oluştur
        // `symbol_resolver`'dan dışa aktarılmış (exported) sembolleri al.
        let mut dynsym_data: Vec<u8> = Vec::new();
        let mut dynstr_data: Vec<u8> = Vec::new();
        dynstr_data.push(0); // İlk bayt null olmalı

        // Dummy ELF Symbol (index 0 for SHT_DYNSYM is always UNDEF with st_name=0)
        dynsym_data.extend_from_slice(&vec![0; 24]); // 24 byte (64-bit için SYM_ENTRY_SIZE)

        // Dışa aktarılmış sembolleri `.dynsym`'e ekle
        let mut dynsym_entry_map: HashMap<String, u32> = HashMap::new(); // Sembol adı -> dynsym_idx
        let mut dynsym_idx_counter: u32 = 1; // 0 index reserved

        for (sym_name, resolved_sym) in symbol_resolver.exported_symbols.iter() {
            let name_offset = dynstr_data.len() as u32;
            dynstr_data.extend_from_slice(sym_name.as_bytes());
            dynstr_data.push(0); // Null terminator

            let mut elf_sym = ElfSymbol {
                name: sym_name.clone(),
                value: resolved_sym.final_address,
                size: resolved_sym.size,
                info: if resolved_sym.section_idx == SHN_UNDEF {
                    (STB_GLOBAL << 4) | STT_NOTYPE // Tanımlı değilse, global ve notype
                } else if resolved_sym.name == config.entry_point_symbol {
                    (STB_GLOBAL << 4) | STT_FUNC
                } else {
                    (STB_GLOBAL << 4) | STT_OBJECT
                },
                other: 0,
                shndx: resolved_sym.section_idx, // Orijinal bölüm indeksi
            };

            let mut sym_entry = vec![0; 24]; // SYM_ENTRY_SIZE
            sym_entry[0..4].copy_from_slice(&name_offset.to_le_bytes());
            sym_entry[4] = elf_sym.info;
            sym_entry[5] = elf_sym.other;
            sym_entry[6..8].copy_from_slice(&elf_sym.shndx.to_le_bytes());
            sym_entry[8..16].copy_from_slice(&elf_sym.value.to_le_bytes());
            sym_entry[16..24].copy_from_slice(&elf_sym.size.to_le_bytes());

            dynsym_data.extend_from_slice(&sym_entry);
            dynsym_entry_map.insert(sym_name.clone(), dynsym_idx_counter);
            dynsym_idx_counter += 1;
        }

        // 3. Global Offset Table (GOT) ve Procedure Linkage Table (PLT) Hazırla
        // Bu tabloların bellek adresleri statik linker tarafından belirlenir.
        // Çalışma zamanında dinamik linker tarafından doldurulurlar.
        // GOT: Veri referansları için. Her bir dış sembol için bir giriş.
        // PLT: Fonksiyon çağrıları için. Her bir dış fonksiyon için bir giriş.
        // Bu bölümlerin boyutlarını hesaplamalıyız.
        // GOT genellike .got.plt veya .got olarak geçer. PLT ise .plt olarak.

        let plt_entry_size: u64 = 16; // Örnek AArch64/RISC-V PLT entry boyutu, x86_64 için 16 veya 8 byte
        let got_entry_size: u64 = 8;  // 64-bit adresler için 8 bayt

        let num_plt_entries = symbol_resolver.exported_symbols.values()
                                .filter(|sym| sym.name != config.entry_point_symbol && sym.section_idx == SHN_UNDEF && sym.size == 0) // Basit fonksiyon filtresi
                                .count() as u64;

        let num_got_entries = symbol_resolver.exported_symbols.len() as u64; // Her dış sembol için bir GOT girişi olabilir.

        let plt_size = plt_entry_size * num_plt_entries; // Fonksiyonlar için
        let got_size = got_entry_size * num_got_entries; // Veriler ve ilk PLT girişi için

        println!("DEBUG: PLT boyutu: {} bayt, GOT boyutu: {} bayt", plt_size, got_size);

        // Bu noktada, bu bölümlerin nihai sanal adresleri henüz belirlenmemiştir.
        // Bunlar, OutputWriter'da ELF dosyasının segmentlerini oluştururken belirlenecektir.
        // Ancak bu bölümlerin varlığını ve boyutlarını LinkerConfig'e veya ObjectFile'a eklemeliyiz.

        // 4. `.dynamic` Bölümünü Oluştur
        // Bu bölüm, dinamik linker'ın çalışması için gerekli meta verileri içerir.
        let mut dynamic_section_data: Vec<u8> = Vec::new();
        let dynamic_entry_size = 16; // tag (8 byte) + val (8 byte)

        // DT_NEEDED girişleri (varsa)
        for lib_name in &self.needed_libraries {
            dynamic_section_data.extend_from_slice(&DT_NEEDED.to_le_bytes());
            // Lib isminin .dynstr'daki offset'ini bulmalıyız
            let str_offset = dynstr_data.iter().enumerate().find(|(_, &b)| b == 0 && dynstr_data[..dynstr_data.len() - 1].ends_with(lib_name.as_bytes())).map(|(idx, _)| idx - lib_name.len()).unwrap_or(0);
            dynamic_section_data.extend_from_slice(&(str_offset as u64).to_le_bytes());
        }

        // DT_PLTGOT (PLT/GOT'un adresi) - Henüz yok, 0 geçici
        dynamic_section_data.extend_from_slice(&DT_PLTGOT.to_le_bytes());
        dynamic_section_data.extend_from_slice(&0u64.to_le_bytes()); // Bu daha sonra düzeltilecek

        // DT_PLTRELSZ, DT_JMPREL (PLT relocationlarının boyutu ve adresi)
        // DT_PLTREL (PLT relocation tipi, örn. R_X86_64_JUMP_SLOT)
        dynamic_section_data.extend_from_slice(&DT_PLTRELSZ.to_le_bytes());
        dynamic_section_data.extend_from_slice(&(plt_size as u64).to_le_bytes()); // PLT boyutunu kullan
        dynamic_section_data.extend_from_slice(&DT_JMPREL.to_le_bytes());
        dynamic_section_data.extend_from_slice(&0u64.to_le_bytes()); // Bu da daha sonra düzeltilecek (PLT relocationlarının başlangıç adresi)
         dynamic_section_data.extend_from_slice(&DT_PLTREL.to_le_bytes());
         dynamic_section_data.extend_from_slice(&(R_X86_64_JUMP_SLOT as u64).to_le_bytes()); // Veya diğer mimariye göre

        // DT_SYMTAB, DT_STRTAB, DT_SYMENT, DT_STRSZ (Dinamik sembol ve string tablosu bilgileri)
        dynamic_section_data.extend_from_slice(&DT_SYMTAB.to_le_bytes());
        dynamic_section_data.extend_from_slice(&0u64.to_le_bytes()); // Bu daha sonra düzeltilecek
        dynamic_section_data.extend_from_slice(&DT_STRTAB.to_le_bytes());
        dynamic_section_data.extend_from_slice(&0u64.to_le_bytes()); // Bu daha sonra düzeltilecek
        dynamic_section_data.extend_from_slice(&DT_SYMENT.to_le_bytes());
        dynamic_section_data.extend_from_slice(&(24u64).to_le_bytes()); // ElfSymbol size (64-bit)
        dynamic_section_data.extend_from_slice(&DT_STRSZ.to_le_bytes());
        dynamic_section_data.extend_from_slice(&(dynstr_data.len() as u64).to_le_bytes());

        // Diğer relocation tabloları (DT_RELA, DT_RELASZ, DT_RELAENT)
        // Eğer varsa, bu tabloya eklenmelidir.
        // Bu örnekte basitleştirilmiş olduğu için sadece JUMP_SLOT/GLOB_DAT ile yetiniyoruz.

        // DT_NULL (Sonlandırıcı)
        dynamic_section_data.extend_from_slice(&DT_NULL.to_le_bytes());
        dynamic_section_data.extend_from_slice(&DT_NULL.to_le_bytes());

        // 5. Yeni Bölümleri ObjectFile'a veya global bir yapıya ekle
        // Bu yeni bölümler (dynsym, dynstr, dynamic, got, plt), nihai çıktıda yer almalıdır.
        // OutputWriter, bunları tanımalı ve yazmalıdır.
        // Şu anda bu bölümler ObjectFile'a doğrudan eklenmiyor,
        // ancak gerçekte bunlar bir `SyntheticSection` veya benzeri bir yapıyla yönetilmelidir.

        // Örneğin, aşağıdaki gibi Sentinel bir ObjectFile oluşturup ona ekleyebiliriz.
        // Veya `Linker` yapısına `synthetic_sections: Vec<ElfSection>` ekleyebiliriz.
        let mut dyn_sym_section = ElfSection {
            name: String::from_str(".dynsym"),
            section_type: SHT_DYNSYM,
            flags: 0, // SHF_ALLOC gibi flag'ler olabilir
            addr: 0, // Runtime'da belirlenecek
            offset: 0, // Runtime'da belirlenecek
            size: dynsym_data.len() as u64,
            link: 0, // .dynstr'ın section indexi
            info: 0,
            addralign: 8,
            entsize: 24, // SYM_ENTRY_SIZE
            data: dynsym_data,
            index: 0, // Geçici
        };
        let mut dyn_str_section = ElfSection {
            name: String::from_str(".dynstr"),
            section_type: SHT_STRTAB,
            flags: 0, // SHF_ALLOC gibi flag'ler olabilir
            addr: 0, // Runtime'da belirlenecek
            offset: 0, // Runtime'da belirlenecek
            size: dynstr_data.len() as u64,
            link: 0,
            info: 0,
            addralign: 1,
            entsize: 0,
            data: dynstr_data,
            index: 0, // Geçici
        };
        let mut dynamic_section = ElfSection {
            name: String::from_str(".dynamic"),
            section_type: 6, // SHT_DYNAMIC
            flags: 0, // SHF_ALLOC | SHF_WRITE
            addr: 0,
            offset: 0,
            size: dynamic_section_data.len() as u64,
            link: 0,
            info: 0,
            addralign: 8,
            entsize: dynamic_entry_size,
            data: dynamic_section_data,
            index: 0, // Geçici
        };

        // GOT ve PLT bölümleri de benzer şekilde oluşturulmalı, ancak initial verileri genellikle 0 veya özel bir stub kodudur.
        // Bu kısımlar, relocator'da veya output_writer'da daha fazla detaylandırılabilir.

        // Bu sentetik bölümleri main Linker yapısına eklemek daha mantıklı olacaktır.
         config.synthetic_sections.push(dyn_sym_section); // Eğer config'te böyle bir alan varsa
         config.synthetic_sections.push(dyn_str_section);
         config.synthetic_sections.push(dynamic_section);

        println!("INFO: Dinamik bağlama yapılandırması tamamlandı.");
        Ok(())
    }

    /// Çalışma zamanı dinamik bağlayıcı fonksiyonu (simülasyon).
    /// Bu fonksiyon, çekirdek (Sahne Karnal) tarafından çağrılacak ve
    /// gerekli kütüphaneleri yükleyip sembolleri çözecektir.
    /// NOT: Bu kod, doğrudan linker'ın parçası olmayacak,
    /// ancak statik linker'ın çıktısı bu dinamik bağlayıcının kullanacağı verileri içermelidir.
    pub fn runtime_dynamic_linker(
        _executable_image: &[u8], // Yüklü yürütülebilir dosyanın ham verisi
        _entry_point: u64,         // Programın giriş noktası adresi
    ) -> Result<()> {
        println!("INFO: Çalışma zamanı dinamik bağlayıcı başlatıldı (Simülasyon).");

        // 1. `.dynamic` segmentini bul ve ayrıştır.
        // 2. `DT_NEEDED` etiketlerini oku ve gerekli paylaşılan kütüphaneleri yükle.
        //    - Bu, çekirdek tarafından sağlanan bir dosya sistemi veya yükleyici API'si gerektirir.
        //    - Yüklenen her kütüphanenin `.dynsym` tablosu ayrıştırılmalı.
        // 3. Sembol çözümleme:
        //    - Uygulamanın çözülmemiş sembollerini (GOT/PLT girişleri) yüklenen kütüphanelerin `.dynsym`'larında ara.
        //    - Eğer sembol bulunursa, GOT/PLT girişlerini sembolün nihai adresiyle doldur.
        // 4. `DT_INIT` fonksiyonlarını çağır (kütüphane başlatma).
        // 5. Programın giriş noktasına atla.

        // Bu, çok yüksek seviyeli bir simülasyondur. Gerçek implementasyon çok daha detaylıdır.
        println!("INFO: Gerekli kütüphaneler yükleniyor ve semboller çözümleniyor...");
        println!("INFO: Çalışma zamanı dinamik bağlama tamamlandı. Program yürütülmeye hazır.");

        // Hata ayıklama için:
         Err(LinkerError::DynamicLinker(DynamicLinkerError::RuntimeError(
             String::from_str("Çalışma zamanı bağlama hatası: Kütüphane bulunamadı.")
         )))
        Ok(())
    }
}
