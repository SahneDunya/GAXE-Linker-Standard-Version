#![no_std]

use crate::linker_config::{LinkerConfig, OutputFormat, LinkerSection};
use crate::object_parser::{ObjectFile, ElfSection, ElfSymbol, SHN_UNDEF, STB_GLOBAL, STT_FUNC, STT_OBJECT, SHT_SYMTAB, SHT_STRTAB, SHT_PROGBITS, SHT_NOBITS};
use crate::symbol_resolver::{SymbolResolver, ResolvedSymbol};
use crate::error::{LinkerError, Result, OutputWriteError};
use sahne64::utils::{String, Vec, HashMap};
use sahne64::{print, println, eprintln};

// ELF Program Header Entry (Phdr) offsets (64-bit için)
// Program yükleyici tarafından kullanılır.
const PHDR_TYPE: usize = 0;    // p_type
const PHDR_FLAGS: usize = 4;   // p_flags
const PHDR_OFFSET: usize = 8;  // p_offset (dosya içindeki offset)
const PHDR_VADDR: usize = 16;  // p_vaddr (bellek sanal adresi)
const PHDR_PADDR: usize = 24;  // p_paddr (fiziksel adres, genellikle vaddr ile aynı)
const PHDR_FILESZ: usize = 32; // p_filesz (dosya üzerindeki boyut)
const PHDR_MEMSZ: usize = 40;  // p_memsz (bellekteki boyut)
const PHDR_ALIGN: usize = 48;  // p_align (hizalama)
const PHDR_ENTRY_SIZE: usize = 56; // Her bir program başlığı girdisinin boyutu

// Segment Tipleri (p_type)
const PT_NULL: u32 = 0;         // Unused
const PT_LOAD: u32 = 1;         // Loadable segment
const PT_DYNAMIC: u32 = 2;      // Dynamic linking information
const PT_INTERP: u32 = 3;       // Path to interpreter
const PT_NOTE: u32 = 4;         // Auxiliary information
const PT_SHLIB: u32 = 5;        // Reserved
const PT_PHDR: u32 = 6;         // Program header table itself

// Segment Bayrakları (p_flags)
const PF_X: u32 = 0x1;          // Executable
const PF_W: u32 = 0x2;          // Writable
const PF_R: u32 = 0x4;          // Readable

/// Dosyaya yazma yardımcı fonksiyonu.
/// Bu fonksiyon Sahne Karnal'ın dosya sistemi API'sine göre implemente edilmelidir.
/// Şimdilik sadece bir yer tutucudur.
fn write_file_content(filepath: &str, data: &[u8]) -> Result<()> {
    // Burada Sahne Karnal'ın dosya yazma sistem çağrısı veya API'si kullanılacak.
    // Örneğin: sahne64::fs::write_file(filepath.as_bytes(), data)?;
    println!("UYARI: Dosya yazma ({}): Bu bir simülasyondur. Veri gerçekten diske yazılmıyor. Boyut: {} bayt", filepath, data.len());
    // Başarılı bir yazma işlemi simüle edelim.
    Ok(())
}

/// Çıktı dosyasını yazan yapı.
pub struct OutputWriter;

impl OutputWriter {
    pub fn new() -> Self {
        OutputWriter
    }

    /// Linklenmiş object dosyalarını ve yapılandırmayı kullanarak nihai çıktıyı yazar.
    ///
    /// `object_files`: Relocations uygulanmış, sembolleri güncellenmiş object dosyaları.
    /// `config`: Linker'ın yapılandırması.
    /// `resolved_symbols_map`: Tüm çözümlenmiş sembollerin haritası (gerekirse sembol tablosu oluşturmak için).
    pub fn write_output(
        &self,
        object_files: &Vec<ObjectFile>,
        config: &LinkerConfig,
        resolved_symbols_map: &HashMap<String, ResolvedSymbol>, // Çözümlenmiş semboller
    ) -> Result<()> {
        println!("INFO: Çıktı dosyası '{}' oluşturuluyor...", config.output_filepath);

        match config.output_format {
            OutputFormat::GaxeExecutable => {
                // Sahne Karnal için ELF64 benzeri bir yürütülebilir dosya yaz.
                self.write_gaxe_executable(object_files, config, resolved_symbols_map)?;
            },
            OutputFormat::IsoImage => {
                // Önyüklenebilir bir ISO imajı yaz.
                self.write_iso_image(object_files, config, resolved_symbols_map)?;
            },
        }

        println!("INFO: Çıktı dosyası başarıyla yazıldı.");
        Ok(())
    }

    /// Sahne Karnal için özel bir ELF64 yürütülebilir dosya yazar.
    /// Bu, ELF başlığı, program başlıkları, segmentler ve bölüm verilerini içerecektir.
    fn write_gaxe_executable(
        &self,
        object_files: &Vec<ObjectFile>,
        config: &LinkerConfig,
        resolved_symbols_map: &HashMap<String, ResolvedSymbol>,
    ) -> Result<()> {
        let mut output_data: Vec<u8> = Vec::new();

        // 1. ELF Başlığını (Header) Oluştur
        // Varsayılan bir 64-bit ELF başlığı.
        let mut elf_header_bytes = vec![0; 64]; // ELF64 header boyutu 64 bayt

        // e_ident
        elf_header_bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']); // Magic
        elf_header_bytes[4] = 2; // EI_CLASS: 64-bit
        elf_header_bytes[5] = 1; // EI_DATA: Little-endian
        elf_header_bytes[6] = 1; // EI_VERSION: Current ELF version
        // Diğer e_ident alanları varsayılan 0 kalabilir

        // e_type (ET_EXEC için 2)
        elf_header_bytes[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
        // e_machine (config.machine, örneğin EM_RISCV)
        // LinkerConfig'e hedef mimari bilgisi eklenmeli veya ilk object dosyasından alınmalı.
        // Şimdilik varsayılan RISC-V diyelim.
        let machine_type = object_files.get(0).map_or(0, |obj| obj.elf_header.machine);
        elf_header_bytes[0x12..0x14].copy_from_slice(&machine_type.to_le_bytes());
        // e_version (1)
        elf_header_bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());

        // e_entry (Giriş noktası sembolünün nihai adresi)
        let entry_address = resolved_symbols_map
            .get(&config.entry_point_symbol)
            .map_or(0, |sym| sym.final_address);
        elf_header_bytes[0x18..0x20].copy_from_slice(&entry_address.to_le_bytes());

        // e_phoff (Program Header Table offset'i - ELF header'dan hemen sonra)
        let phdr_offset = elf_header_bytes.len() as u64;
        elf_header_bytes[0x20..0x28].copy_from_slice(&phdr_offset.to_le_bytes());
        // e_shoff (Section Header Table offset'i - tüm segmentler ve veriler bittikten sonra)
        // Bu daha sonra hesaplanacak.

        // e_flags (Mimariye özgü bayraklar)
        // Şu an için 0. RISC-V için RVC (Compressed) gibi bayraklar olabilir.
        elf_header_bytes[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());

        // e_ehsize (ELF header boyutu)
        elf_header_bytes[0x34..0x36].copy_from_slice(&(elf_header_bytes.len() as u16).to_le_bytes());
        // e_phentsize (Program Header entry boyutu)
        elf_header_bytes[0x36..0x38].copy_from_slice(&(PHDR_ENTRY_SIZE as u16).to_le_bytes());

        // 2. Program Header Tablosunu (Program Headers) Oluştur
        // Her `LinkerSection` için bir `PT_LOAD` segmenti oluşturacağız.
        // Not: Gerçekte, linker aynı özelliklere sahip birden fazla bölümü tek bir segmente birleştirebilir.
        // Örneğin, .text ve .rodata tek bir okunabilir segment olabilir.
        let mut program_headers_bytes: Vec<u8> = Vec::new();
        let mut segments_data: Vec<u8> = Vec::new(); // Tüm segmentlerin birleşmiş ham verisi
        let mut current_file_offset = phdr_offset + (config.sections.len() as u64 * PHDR_ENTRY_SIZE as u64); // Program Header'lardan sonraki offset

        let mut section_to_segment_map: HashMap<String, (u64, u64)> = HashMap::new(); // (vaddr, file_offset)

        // Bölümleri .laxe betiğindeki sıraya göre işle
        for linker_section_config in config.sections.iter() {
            let mut segment_data_for_section: Vec<u8> = Vec::new();
            let mut segment_vaddr = linker_section_config.address.unwrap_or(0); // .laxe'den gelen vaddr
            let mut segment_memsz = 0u64;
            let mut segment_filesz = 0u64;
            let mut flags = PF_R; // Varsayılan okunabilir

            match linker_section_config.name.as_str() {
                ".text" => flags |= PF_X, // Yürütülebilir
                ".data" | ".bss" => flags |= PF_W, // Yazılabilir
                ".rodata" => { /* Sadece okunabilir, varsayılan */ },
                _ => { /* Diğerleri */ }
            }

            // Bu bölüme ait tüm object dosyalarındaki verileri topla
            for obj_file in object_files.iter() {
                for obj_section in obj_file.sections.iter() {
                    if obj_section.name == linker_section_config.name {
                        // Obj_section'ın verisini topla
                        if obj_section.section_type == SHT_PROGBITS {
                             segment_data_for_section.extend_from_slice(&obj_section.data);
                             segment_filesz += obj_section.data.len() as u64;
                             segment_memsz += obj_section.data.len() as u64;
                        } else if obj_section.section_type == SHT_NOBITS {
                            // .bss gibi bölümler diskte yer kaplamaz, ancak bellekte yer ayrılır.
                            segment_memsz += obj_section.size;
                        }
                    }
                }
            }

            // Segment verisini birleştirilmiş data'ya ekle
            let segment_file_offset = current_file_offset;
            segments_data.extend_from_slice(&segment_data_for_section);
            current_file_offset += segment_filesz;

            // Program Header girişini oluştur
            let mut phdr_entry = vec![0; PHDR_ENTRY_SIZE];
            phdr_entry[PHDR_TYPE..PHDR_TYPE + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            phdr_entry[PHDR_FLAGS..PHDR_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
            phdr_entry[PHDR_OFFSET..PHDR_OFFSET + 8].copy_from_slice(&segment_file_offset.to_le_bytes());
            phdr_entry[PHDR_VADDR..PHDR_VADDR + 8].copy_from_slice(&segment_vaddr.to_le_bytes());
            phdr_entry[PHDR_PADDR..PHDR_PADDR + 8].copy_from_slice(&segment_vaddr.to_le_bytes()); // Genellikle aynı
            phdr_entry[PHDR_FILESZ..PHDR_FILESZ + 8].copy_from_slice(&segment_filesz.to_le_bytes());
            phdr_entry[PHDR_MEMSZ..PHDR_MEMSZ + 8].copy_from_slice(&segment_memsz.to_le_bytes());
            phdr_entry[PHDR_ALIGN..PHDR_ALIGN + 8].copy_from_slice(&4096u64.to_le_bytes()); // Sayfa hizalaması
            program_headers_bytes.extend_from_slice(&phdr_entry);

            section_to_segment_map.insert(linker_section_config.name.clone(), (segment_vaddr, segment_file_offset));
        }

        // 3. Sembol Tablosu ve String Tablosu Oluşturma (Opsiyonel ama hata ayıklama için faydalı)
        let mut symbol_table_bytes: Vec<u8> = Vec::new();
        let mut symbol_string_table_bytes: Vec<u8> = Vec::new(); // .strtab
        symbol_string_table_bytes.push(0); // İlk bayt her zaman null olmalı

        // SHT_NULL sembolü için dummy bir giriş ekle
        let mut dummy_symbol_entry = vec![0; PHDR_ENTRY_SIZE]; // Sembol girişi boyutu SYM_ENTRY_SIZE'dan gelmeli
        symbol_table_bytes.extend_from_slice(&dummy_symbol_entry);

        for resolved_sym in resolved_symbols_map.values() {
            let mut elf_sym = ElfSymbol {
                name: resolved_sym.name.clone(),
                value: resolved_sym.final_address, // Nihai adres
                size: resolved_sym.size,
                info: if resolved_sym.name == config.entry_point_symbol {
                    (STB_GLOBAL << 4) | STT_FUNC // Giriş noktası global fonksiyon
                } else if resolved_sym.section_idx == SHN_UNDEF {
                    (STB_GLOBAL << 4) | STT_NOTYPE // Tanımlanmamış sembol, global
                } else {
                    (STB_GLOBAL << 4) | STT_OBJECT // Varsayılan olarak global obje
                },
                other: 0,
                shndx: resolved_sym.section_idx, // Orijinal bölüm indeksi
            };

            // Sembol ismini string tablosuna ekle
            let name_offset = symbol_string_table_bytes.len() as u32;
            symbol_string_table_bytes.extend_from_slice(resolved_sym.name.as_bytes());
            symbol_string_table_bytes.push(0); // Null terminator

            // Sembol tablosu girdisini oluştur
            let mut sym_entry = vec![0; 24]; // SYM_ENTRY_SIZE 24 varsayalım
            sym_entry[0..4].copy_from_slice(&name_offset.to_le_bytes());
            sym_entry[4] = elf_sym.info;
            sym_entry[5] = elf_sym.other;
            sym_entry[6..8].copy_from_slice(&elf_sym.shndx.to_le_bytes());
            sym_entry[8..16].copy_from_slice(&elf_sym.value.to_le_bytes());
            sym_entry[16..24].copy_from_slice(&elf_sym.size.to_le_bytes());
            symbol_table_bytes.extend_from_slice(&sym_entry);
        }

        // 4. Section Header Table ve Section Header String Table Oluşturma
        // Bu kısım genellikle Program Header'lardan sonra yer alır.
        // Şu an için çok detaylı bir Section Header Table oluşturmayacağız,
        // çünkü programın yüklenmesi için Program Header'lar daha önemlidir.
        // Hata ayıklama veya dinamik bağlama için bu tablolara ihtiyaç duyulur.
        let mut section_header_table_bytes: Vec<u8> = Vec::new();
        let mut section_header_string_table_data: Vec<u8> = Vec::new(); // .shstrtab
        section_header_string_table_data.push(0); // İlk bayt null

        // İlk Section Header: SHT_NULL (Boş Section Header)
        section_header_table_bytes.extend_from_slice(&vec![0; 64]); // SHDR_ENTRY_SIZE 64 varsayalım.

        // .shstrtab bölümü için Section Header oluştur
        let shstrtab_name_offset = section_header_string_table_data.len() as u32;
        section_header_string_table_data.extend_from_slice(b".shstrtab");
        section_header_string_table_data.push(0);
        
        let shstrtab_shdr_start = current_file_offset; // .shstrtab'ın dosyadaki başlangıç offseti
        let mut shstrtab_shdr_entry = vec![0; 64];
        shstrtab_shdr_entry[0..4].copy_from_slice(&shstrtab_name_offset.to_le_bytes());
        shstrtab_shdr_entry[4..8].copy_from_slice(&SHT_STRTAB.to_le_bytes()); // Type
        shstrtab_shdr_entry[24..32].copy_from_slice(&shstrtab_shdr_start.to_le_bytes()); // Offset
        shstrtab_shdr_entry[32..40].copy_from_slice(&(section_header_string_table_data.len() as u64).to_le_bytes()); // Size
        section_header_table_bytes.extend_from_slice(&shstrtab_shdr_entry);
        
        current_file_offset += section_header_string_table_data.len() as u64;


        // .symtab bölümü için Section Header oluştur
        let symtab_name_offset = section_header_string_table_data.len() as u32;
        section_header_string_table_data.extend_from_slice(b".symtab");
        section_header_string_table_data.push(0);

        let symtab_shdr_start = current_file_offset;
        let mut symtab_shdr_entry = vec![0; 64];
        symtab_shdr_entry[0..4].copy_from_slice(&symtab_name_offset.to_le_bytes());
        symtab_shdr_entry[4..8].copy_from_slice(&SHT_SYMTAB.to_le_bytes()); // Type
        symtab_shdr_entry[24..32].copy_from_slice(&symtab_shdr_start.to_le_bytes()); // Offset
        symtab_shdr_entry[32..40].copy_from_slice(&(symbol_table_bytes.len() as u64).to_le_bytes()); // Size
        symtab_shdr_entry[56..64].copy_from_slice(&(24u64).to_le_bytes()); // Entry size (SYM_ENTRY_SIZE)
        section_header_table_bytes.extend_from_slice(&symtab_shdr_entry);

        current_file_offset += symbol_table_bytes.len() as u64;


        // .strtab bölümü için Section Header oluştur (sembol isimleri için)
        let strtab_name_offset = section_header_string_table_data.len() as u32;
        section_header_string_table_data.extend_from_slice(b".strtab");
        section_header_string_table_data.push(0);

        let strtab_shdr_start = current_file_offset;
        let mut strtab_shdr_entry = vec![0; 64];
        strtab_shdr_entry[0..4].copy_from_slice(&strtab_name_offset.to_le_bytes());
        strtab_shdr_entry[4..8].copy_from_slice(&SHT_STRTAB.to_le_bytes()); // Type
        strtab_shdr_entry[24..32].copy_from_slice(&strtab_shdr_start.to_le_bytes()); // Offset
        strtab_shdr_entry[32..40].copy_from_slice(&(symbol_string_table_bytes.len() as u64).to_le_bytes()); // Size
        section_header_table_bytes.extend_from_slice(&strtab_shdr_entry);

        current_file_offset += symbol_string_table_bytes.len() as u64;


        // ELF Header'daki e_phnum ve e_shnum, e_shoff ve e_shstrndx'i güncelle
        elf_header_bytes[0x3A..0x3C].copy_from_slice(&(config.sections.len() as u16).to_le_bytes()); // e_phnum
        
        let total_shnum = 1 + 2 + 1; // Null + .shstrtab + .symtab + .strtab (basitlik için)
        elf_header_bytes[0x3C..0x3E].copy_from_slice(&(total_shnum as u16).to_le_bytes()); // e_shnum
        
        let shoff = current_file_offset;
        elf_header_bytes[0x28..0x30].copy_from_slice(&shoff.to_le_bytes()); // e_shoff

        // shstrtab'ın section header tablosundaki dizini bul
        // 0: Null, 1: .shstrtab, 2: .symtab, 3: .strtab
        elf_header_bytes[0x3E..0x40].copy_from_slice(&(1u16).to_le_bytes()); // e_shstrndx

        // Tüm parçaları birleştirerek nihai çıktıyı oluştur
        output_data.extend_from_slice(&elf_header_bytes);
        output_data.extend_from_slice(&program_headers_bytes);
        output_data.extend_from_slice(&segments_data); // Kod ve veri buraya gelir
        output_data.extend_from_slice(&symbol_table_bytes);
        output_data.extend_from_slice(&symbol_string_table_bytes);
        output_data.extend_from_slice(&section_header_string_table_data);
        output_data.extend_from_slice(&section_header_table_bytes);
        
        // Son olarak dosyayı yaz
        write_file_content(&config.output_filepath, &output_data)
    }

    /// Önyüklenebilir bir ISO imajı yazar.
    /// Bu, genellikle ELF dosyasını ve diğer gerekli boot dosyalarını bir ISO standardına göre paketlemeyi içerir.
    /// Çok daha karmaşık bir konudur ve burada sadece temel bir yapı simüle edilmiştir.
    fn write_iso_image(
        &self,
        _object_files: &Vec<ObjectFile>,
        config: &LinkerConfig,
        _resolved_symbols_map: &HashMap<String, ResolvedSymbol>,
    ) -> Result<()> {
        println!("INFO: ISO imajı oluşturma başlatıldı. Bu, basit bir yer tutucudur.");

        // ISO 9660 standardı ve El Torito uzantısı çok karmaşıktır.
        // Genellikle şunları içerir:
        // - Boot Record (El Torito)
        // - Primary Volume Descriptor
        // - Directory records
        // - Dosya verileri
        // - Padding
        // Çekirdeğinizi (daha önce oluşturulmuş .gaxe veya ham ikili) bir sektörde yerleştirmek gerekir.

        let mut iso_data: Vec<u8> = Vec::new();
        let sector_size = 2048; // CD/DVD sektör boyutu

        // Basit bir örnek: Sadece çekirdek verisini ilk sektörlere yazalım.
        // Gerçekte, bir ELF dosyasını ISO'ya dönüştürmek için iso9660 kütüphaneleri kullanılır.
        
        // Örnek: Çekirdek verisini al (burada `main.rs` dosyasında yazılan ELF'in içeriği olmalı)
        // Bunun için `write_gaxe_executable`'dan dönen veriyi buraya aktarmanın bir yolu olmalı
        // veya bu fonksiyon doğrudan ELF dosyasını oluşturmalı.
        // Şimdilik sadece bir "dummy" çekirdek içeriği oluşturalım.
        let mut dummy_kernel_data = Vec::new();
        dummy_kernel_data.extend_from_slice(b"GAXE KERNEL BOOTSTRAP!");
        dummy_kernel_data.resize(sector_size, 0); // Bir sektörü doldur

        iso_data.extend_from_slice(&dummy_kernel_data);

        // Ek sektörler (örneğin boot catalog, volume descriptors vb.)
        // Her biri 2048 baytlık bir bloktur.

        // Toplam ISO imajı boyutu (birkaç dummy sektörle)
        let total_iso_size = 16 * sector_size; // Örneğin 16 sektör
        iso_data.resize(total_iso_size, 0);

        write_file_content(&config.output_filepath, &iso_data)
    }
}
