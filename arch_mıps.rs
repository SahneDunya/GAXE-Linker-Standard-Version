#![no_std]

use crate::error::{LinkerError, Result, ObjectParseError};
use sahne64::utils::{String, Vec, HashMap, fmt}; // no_std uyumlu String, Vec, HashMap

// ELF Sabitleri (Örnek - Genellikle tam bir kütüphane gerekir)
// Bu değerler gerçek ELF spesifikasyonundan alınmıştır.
// Kaynak: https://refspecs.linuxfoundation.org/elf/gabi-elf.html

// e_ident (ELF Identifier) dizini offsetleri
const EI_MAG0: usize = 0;   // File identification
const EI_MAG1: usize = 1;   // File identification
const EI_MAG2: usize = 2;   // File identification
const EI_MAG3: usize = 3;   // File identification
const EI_CLASS: usize = 4;  // File class (32-bit or 64-bit)
const EI_DATA: usize = 5;   // Data encoding (endianness)
const EI_VERSION: usize = 6; // ELF header version
const EI_OSABI: usize = 7;  // OS/ABI identification
const EI_ABIVERSION: usize = 8; // ABI version
const EI_NIDENT: usize = 16; // Size of e_ident

// EI_CLASS değerleri
const ELFCLASSNONE: u8 = 0;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2; // 64-bit object

// EI_DATA değerleri
const ELFDATANONE: u8 = 0;
const ELFDATA2LSB: u8 = 1; // Little-endian
const ELFDATA2MSB: u8 = 2; // Big-endian

// e_type (Object File Type) değerleri
const ET_NONE: u16 = 0;    // No file type
const ET_REL: u16 = 1;     // Relocatable file (.o)
const ET_EXEC: u16 = 2;    // Executable file
const ET_DYN: u16 = 3;     // Shared object file
const ET_CORE: u16 = 4;    // Core file

// e_machine (Architecture) değerleri (Örnekler)
// Bu değerler tüm mimarileri kapsamaz, sadece örneklerdir.
const EM_NONE: u16 = 0;
const EM_MIPS: u16 = 8;
const EM_X86_64: u16 = 62; // AMD x86-64 architecture
const EM_AARCH64: u16 = 183; // AArch64
const EM_RISCV: u16 = 243; // RISC-V

// Section Header Table Entry (Shdr) offsets (64-bit için)
const SHDR_NAME: usize = 0; // sh_name
const SHDR_TYPE: usize = 4; // sh_type
const SHDR_FLAGS: usize = 8; // sh_flags
const SHDR_ADDR: usize = 16; // sh_addr
const SHDR_OFFSET: usize = 24; // sh_offset (dosya içindeki offset)
const SHDR_SIZE: usize = 32; // sh_size (bölümün boyutu)
const SHDR_LINK: usize = 40; // sh_link
const SHDR_INFO: usize = 44; // sh_info
const SHDR_ALIGN: usize = 48; // sh_addralign
const SHDR_ENTSIZE: usize = 56; // sh_entsize
const SHDR_ENTRY_SIZE: usize = 64; // Her bir bölüm başlığı girdisinin boyutu

// Section Types (sh_type)
const SHT_NULL: u32 = 0;          // Inactive
const SHT_PROGBITS: u32 = 1;      // Program data
const SHT_SYMTAB: u32 = 2;        // Symbol table
const SHT_STRTAB: u32 = 3;        // String table
const SHT_RELA: u32 = 4;          // Relocation entries with addends
const SHT_HASH: u32 = 5;          // Symbol hash table
const SHT_DYNAMIC: u32 = 6;       // Dynamic linking information
const SHT_NOTE: u32 = 7;          // Notes
const SHT_NOBITS: u32 = 8;        // Program space with no data (.bss)
const SHT_REL: u32 = 9;           // Relocation entries, no addends
const SHT_SHLIB: u32 = 10;        // Reserved
const SHT_DYNSYM: u32 = 11;       // Dynamic linker symbol table

// Symbol Table Entry (Sym) offsets (64-bit için)
const SYM_NAME: usize = 0;   // st_name
const SYM_INFO: usize = 4;   // st_info
const SYM_OTHER: usize = 5;  // st_other
const SYM_SHNDX: usize = 6;  // st_shndx (Section index)
const SYM_VALUE: usize = 8;  // st_value
const SYM_SIZE: usize = 16;  // st_size
const SYM_ENTRY_SIZE: usize = 24; // Her bir sembol tablosu girdisinin boyutu

// Relocation Entry (Rela) offsets (64-bit için)
const RELA_OFFSET: usize = 0;   // r_offset
const RELA_INFO: usize = 8;     // r_info (sembol ve tip)
const RELA_ADDEND: usize = 16;  // r_addend
const RELA_ENTRY_SIZE: usize = 24; // Her bir yeniden konumlandırma girdisinin boyutu

// Yardımcı fonksiyon: Belirli bir offsetten belirli boyutta unsigned integer oku
fn read_u64_le(data: &[u8], offset: usize) -> Result<u64> {
    if data.len() < offset + 8 {
        return Err(LinkerError::ObjectParse(ObjectParseError::InvalidOffset(
            String::from_format_args!("{} adresinden 64-bit okuma hatası, veri boyutu yetersiz.", offset)
        )));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    Ok(u64::from_le_bytes(bytes))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    if data.len() < offset + 4 {
        return Err(LinkerError::ObjectParse(ObjectParseError::InvalidOffset(
            String::from_format_args!("{} adresinden 32-bit okuma hatası, veri boyutu yetersiz.", offset)
        )));
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&data[offset..offset + 4]);
    Ok(u32::from_le_bytes(bytes))
}

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    if data.len() < offset + 2 {
        return Err(LinkerError::ObjectParse(ObjectParseError::InvalidOffset(
            String::from_format_args!("{} adresinden 16-bit okuma hatası, veri boyutu yetersiz.", offset)
        )));
    }
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&data[offset..offset + 2]);
    Ok(u16::from_le_bytes(bytes))
}

/// ELF Section (Bölüm) yapısı.
#[derive(Debug, Clone)]
pub struct ElfSection {
    pub name: String,        // Bölüm adı (örn: .text, .data)
    pub section_type: u32,   // SHT_PROGBITS, SHT_SYMTAB vb.
    pub flags: u64,          // SHF_ALLOC, SHF_EXECINSTR vb.
    pub addr: u64,           // Bölümün sanal adresi (genellikle 0 .o dosyalarında)
    pub offset: u64,         // Dosya içindeki offset
    pub size: u64,           // Bölümün boyutu
    pub link: u32,           // sh_link alanı (ilgili tablo dizini)
    pub info: u32,           // sh_info alanı
    pub addralign: u64,      // Hizalama gereksinimi
    pub entsize: u64,        // Giriş boyutu (örn: sembol tablosu için)
    pub data: Vec<u8>,       // Bölümün ham verisi
    pub index: usize,        // Kendi dizini (shndx'e karşılık)
}

/// ELF Symbol (Sembol) yapısı.
#[derive(Debug, Clone)]
pub struct ElfSymbol {
    pub name: String,        // Sembol adı
    pub value: u64,          // Sembolün değeri (genellikle bölüm içi offset)
    pub size: u64,           // Sembolün boyutu
    pub info: u8,            // Sembol tipi ve bağlama (STB_LOCAL, STB_GLOBAL, STT_FUNC vb.)
    pub other: u8,           // st_other alanı
    pub shndx: u16,          // İlgili bölümün dizini (SHN_UNDEF, SHN_ABS, SHN_COMMON, section index)
}

impl ElfSymbol {
    // Yardımcı fonksiyonlar: Sembol tipini ve bağlamayı çözmek için
    pub fn bind(&self) -> u8 {
        self.info >> 4
    }
    pub fn typ(&self) -> u8 {
        self.info & 0x0F
    }
}

/// ELF Relocation (Yeniden Konumlandırma) yapısı (Rela tipi, yani addend'li).
#[derive(Debug, Clone)]
pub struct ElfRelocation {
    pub offset: u64,      // Yeniden konumlandırma uygulanacak offset
    pub info: u64,        // Sembol dizini ve relocation tipi
    pub addend: i64,      // Ekleyic (addend)
    pub symbol_index: u32, // Bilgilendirme: info'dan çıkarılan sembol dizini
    pub typ: u32,          // Bilgilendirme: info'dan çıkarılan relocation tipi
}

impl ElfRelocation {
    // info alanından sembol dizinini ve tipi çıkarma
    pub fn r_sym(&self) -> u32 {
        (self.info >> 32) as u32
    }
    pub fn r_type(&self) -> u32 {
        self.info as u32
    }
}

/// Ayrıştırılan bir object dosyasının temsilcisi.
#[derive(Debug, Clone)]
pub struct ObjectFile {
    pub filename: String,
    pub elf_header: ElfHeader,
    pub sections: Vec<ElfSection>,
    pub symbols: Vec<ElfSymbol>,
    pub relocations: Vec<ElfRelocation>,
    pub string_table_data: Vec<u8>, // .strtab'ın ham verisi
    pub symbol_string_table_data: Vec<u8>, // .symtab'ın string tablosu
    // Gelecekte eklenebilecek: dinamik bağlama bilgileri, mimariye özgü bayraklar
}

/// ELF Header yapısı.
#[derive(Debug, Clone)]
pub struct ElfHeader {
    pub ident: [u8; EI_NIDENT], // e_ident
    pub typ: u16,               // e_type
    pub machine: u16,           // e_machine
    pub version: u32,           // e_version
    pub entry: u64,             // e_entry (genellikle 0 for .o files)
    pub phoff: u64,             // e_phoff (Program Header Table offset)
    pub shoff: u64,             // e_shoff (Section Header Table offset)
    pub flags: u32,             // e_flags
    pub ehsize: u16,            // e_ehsize (ELF header size)
    pub phentsize: u16,         // e_phentsize (Program Header entry size)
    pub phnum: u16,             // e_phnum (Number of Program Header entries)
    pub shentsize: u16,         // e_shentsize (Section Header entry size)
    pub shnum: u16,             // e_shnum (Number of Section Header entries)
    pub shstrndx: u16,          // e_shstrndx (Section header string table index)
}

/// Object dosyalarını ayrıştıran yapı.
pub struct ObjectParser;

impl ObjectParser {
    pub fn new() -> Self {
        ObjectParser
    }

    /// Ham bayt verisinden bir ELF object dosyasını ayrıştırır.
    pub fn parse(&self, data: &[u8]) -> Result<ObjectFile> {
        if data.len() < EI_NIDENT {
            return Err(LinkerError::ObjectParse(ObjectParseError::InvalidFormat(
                String::from_str("ELF kimliği için yeterli veri yok.")
            )));
        }

        // 1. ELF Header'ı Ayrıştır (e_ident kısmı)
        if data[EI_MAG0] != 0x7f || data[EI_MAG1] != b'E' || data[EI_MAG2] != b'L' || data[EI_MAG3] != b'F' {
            return Err(LinkerError::ObjectParse(ObjectParseError::InvalidMagic));
        }
        if data[EI_CLASS] != ELFCLASS64 {
            return Err(LinkerError::ObjectParse(ObjectParseError::UnsupportedArchitecture(
                String::from_str("Sadece 64-bit ELF dosyaları desteklenmektedir.")
            )));
        }
        if data[EI_DATA] != ELFDATA2LSB {
            return Err(LinkerError::ObjectParse(ObjectParseError::UnsupportedEndianness(
                String::from_str("Sadece Little-Endian ELF dosyaları desteklenmektedir.")
            )));
        }

        let header_offset = EI_NIDENT; // e_ident'tan sonraki offset

        let typ = read_u16_le(data, header_offset)?;
        let machine = read_u16_le(data, header_offset + 2)?;
        let version = read_u32_le(data, header_offset + 4)?;
        let entry = read_u64_le(data, header_offset + 8)?;
        let phoff = read_u64_le(data, header_offset + 16)?;
        let shoff = read_u64_le(data, header_offset + 24)?;
        let flags = read_u32_le(data, header_offset + 32)?;
        let ehsize = read_u16_le(data, header_offset + 36)?;
        let phentsize = read_u16_le(data, header_offset + 38)?;
        let phnum = read_u16_le(data, header_offset + 40)?;
        let shentsize = read_u16_le(data, header_offset + 42)?;
        let shnum = read_u16_le(data, header_offset + 44)?;
        let shstrndx = read_u16_le(data, header_offset + 46)?;

        let elf_header = ElfHeader {
            ident: {
                let mut ident_arr = [0u8; EI_NIDENT];
                ident_arr.copy_from_slice(&data[0..EI_NIDENT]);
                ident_arr
            },
            typ,
            machine,
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        };

        if elf_header.typ != ET_REL {
            return Err(LinkerError::ObjectParse(ObjectParseError::InvalidFileType(
                String::from_str("Sadece relocatable (.o) dosyaları desteklenmektedir.")
            )));
        }
        // Desteklenen mimariyi kontrol et (gelen machine kodu ile)
        // Bu kısım, derleyicinizdeki TargetArch enum'undan gelen mimarilerle eşleşmelidir.
        // Şimdilik sadece örnek olarak x86_64, AArch64, RISC-V, MIPS'i kontrol ediyoruz.
        match elf_header.machine {
            EM_X86_64 | EM_AARCH64 | EM_RISCV | EM_MIPS => { /* Destekleniyor */ }
            _ => return Err(LinkerError::ObjectParse(ObjectParseError::UnsupportedArchitecture(
                String::from_format_args!("Desteklenmeyen ELF mimarisi: {}", elf_header.machine)
            ))),
        }

        // 2. Section Header Table'ı Ayrıştır
        let mut sections: Vec<ElfSection> = Vec::new();
        let shstrtab_data: Vec<u8>; // Bölüm isimleri string tablosu

        if shnum == 0 {
             return Err(LinkerError::ObjectParse(ObjectParseError::InvalidFormat(
                String::from_str("ELF dosyası bölüm başlığı tablosu içermiyor.")
            )));
        }
        if shstrndx as usize >= shnum as usize {
            return Err(LinkerError::ObjectParse(ObjectParseError::InvalidFormat(
                String::from_str("Geçersiz shstrndx değeri.")
            )));
        }

        // Önce section header string table'ı bul ve oku
        let shstrtab_shdr_offset = shoff as usize + (shstrndx as usize * shentsize as usize);
        if data.len() < shstrtab_shdr_offset + shentsize as usize {
             return Err(LinkerError::ObjectParse(ObjectParseError::InvalidOffset(
                String::from_str("Section Header String Table konumu geçersiz.")
            )));
        }
        let shstrtab_offset = read_u64_le(data, shstrtab_shdr_offset + SHDR_OFFSET)?;
        let shstrtab_size = read_u64_le(data, shstrtab_shdr_offset + SHDR_SIZE)?;
        if data.len() < shstrtab_offset as usize + shstrtab_size as usize {
            return Err(LinkerError::ObjectParse(ObjectParseError::InvalidOffset(
                String::from_str("Section Header String Table verisi geçersiz.")
            )));
        }
        shstrtab_data = data[shstrtab_offset as usize .. (shstrtab_offset + shstrtab_size) as usize].to_vec();


        for i in 0..shnum {
            let shdr_start = shoff as usize + (i as usize * shentsize as usize);
            if data.len() < shdr_start + shentsize as usize {
                 return Err(LinkerError::ObjectParse(ObjectParseError::InvalidOffset(
                    String::from_format_args!("{} indeksli bölüm başlığı konumu geçersiz.", i)
                )));
            }

            let name_offset = read_u32_le(data, shdr_start + SHDR_NAME)?;
            let section_type = read_u32_le(data, shdr_start + SHDR_TYPE)?;
            let flags = read_u64_le(data, shdr_start + SHDR_FLAGS)?;
            let addr = read_u64_le(data, shdr_start + SHDR_ADDR)?;
            let offset = read_u64_le(data, shdr_start + SHDR_OFFSET)?;
            let size = read_u64_le(data, shdr_start + SHDR_SIZE)?;
            let link = read_u32_le(data, shdr_start + SHDR_LINK)?;
            let info = read_u32_le(data, shdr_start + SHDR_INFO)?;
            let addralign = read_u64_le(data, shdr_start + SHDR_ALIGN)?;
            let entsize = read_u64_le(data, shdr_start + SHDR_ENTSIZE)?;

            let section_name = Self::read_string_from_bytes(&shstrtab_data, name_offset as usize)?;

            let section_data_slice = if offset as usize + size as usize > data.len() || section_type == SHT_NOBITS {
                // SHT_NOBITS (örn: .bss) bölümlerinin verisi diskte yer kaplamaz.
                // Veya boyut/offset hatalıysa boş veri al.
                &[]
            } else {
                &data[offset as usize .. (offset + size) as usize]
            };

            sections.push(ElfSection {
                name: section_name,
                section_type,
                flags,
                addr,
                offset,
                size,
                link,
                info,
                addralign,
                entsize,
                data: section_data_slice.to_vec(),
                index: i as usize,
            });
        }

        // 3. Sembol Tablolarını ve Relocation Girişlerini Ayrıştır
        let mut symbols: Vec<ElfSymbol> = Vec::new();
        let mut relocations: Vec<ElfRelocation> = Vec::new();
        let mut symbol_string_table_data: Vec<u8> = Vec::new(); // .symtab'ın kendi string tablosu (.strtab)

        for section_idx in 0..sections.len() {
            let section = &sections[section_idx];

            match section.section_type {
                SHT_SYMTAB | SHT_DYNSYM => {
                    // Sembol tablosu bölümü (.symtab veya .dynsym)
                    if section.link as usize >= sections.len() {
                        return Err(LinkerError::ObjectParse(ObjectParseError::InvalidFormat(
                            String::from_format_args!("Sembol tablosu ({}) için geçersiz sh_link (string tablosu dizini).", section.name)
                        )));
                    }
                    symbol_string_table_data = sections[section.link as usize].data.clone();

                    let num_symbols = section.size / section.entsize;
                    for i in 0..num_symbols {
                        let sym_start = (i * section.entsize) as usize;
                        if section.data.len() < sym_start + SYM_ENTRY_SIZE {
                            return Err(LinkerError::ObjectParse(ObjectParseError::InvalidOffset(
                                String::from_str("Sembol tablosu girdisi yetersiz veri.")
                            )));
                        }

                        let name_offset = read_u32_le(&section.data, sym_start + SYM_NAME)?;
                        let info = section.data[sym_start + SYM_INFO];
                        let other = section.data[sym_start + SYM_OTHER];
                        let shndx = read_u16_le(&section.data, sym_start + SYM_SHNDX)?;
                        let value = read_u64_le(&section.data, sym_start + SYM_VALUE)?;
                        let size = read_u64_le(&section.data, sym_start + SYM_SIZE)?;

                        let symbol_name = Self::read_string_from_bytes(&symbol_string_table_data, name_offset as usize)?;
                        symbols.push(ElfSymbol {
                            name: symbol_name,
                            value,
                            size,
                            info,
                            other,
                            shndx,
                        });
                    }
                },
                SHT_RELA => {
                    // Relocation tablosu (.rela.text, .rela.data vb.)
                    let num_relocations = section.size / section.entsize;
                    for i in 0..num_relocations {
                        let rela_start = (i * section.entsize) as usize;
                        if section.data.len() < rela_start + RELA_ENTRY_SIZE {
                            return Err(LinkerError::ObjectParse(ObjectParseError::InvalidOffset(
                                String::from_str("Relocation tablosu girdisi yetersiz veri.")
                            )));
                        }

                        let offset = read_u64_le(&section.data, rela_start + RELA_OFFSET)?;
                        let info = read_u64_le(&section.data, rela_start + RELA_INFO)?;
                        let addend = i64::from_le_bytes(section.data[rela_start + RELA_ADDEND .. rela_start + RELA_ADDEND + 8].try_into().unwrap());

                        relocations.push(ElfRelocation {
                            offset,
                            info,
                            addend,
                            symbol_index: (info >> 32) as u32, // Sembol dizinini info'dan çıkar
                            typ: info as u32,                   // Relocation tipini info'dan çıkar
                        });
                    }
                },
                _ => { /* Diğer bölüm tipleri şimdilik atlanabilir */ }
            }
        }

        Ok(ObjectFile {
            filename: String::from_str("unknown.o"), // Gerçek isim dışarıdan verilmeli
            elf_header,
            sections,
            symbols,
            relocations,
            string_table_data: shstrtab_data, // Genel string tablosu
            symbol_string_table_data, // Sembol string tablosu
        })
    }

    /// Bayt dizisinden null-terminated bir string okur.
    fn read_string_from_bytes(data: &[u8], offset: usize) -> Result<String> {
        let mut end = offset;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }
        if end > data.len() {
            return Err(LinkerError::ObjectParse(ObjectParseError::InvalidOffset(
                String::from_format_args!("String okuma hatası: {} adresinden başlayan null-terminated string bulunamadı.", offset)
            )));
        }
        let slice = &data[offset..end];
        String::from_utf8(slice.to_vec())
            .map_err(|_| LinkerError::ObjectParse(ObjectParseError::InvalidUtf8(
                String::from_format_args!("Geçersiz UTF-8 string: {:?}", slice)
            )))
    }
}
