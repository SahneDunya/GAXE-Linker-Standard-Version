// relocator.rs
#![no_std]

use crate::linker_config::{LinkerConfig, OutputFormat};
use crate::object_parser::{ObjectFile, ElfRelocation, ElfSymbol, ElfSection, EM_X86_64, EM_AARCH64, EM_RISCV, EM_MIPS};
use crate::symbol_resolver::{SymbolResolver, ResolvedSymbol};
use crate::error::{LinkerError, Result, RelocationError};
use sahne64::utils::{String, Vec, HashMap};
use sahne64::{print, println, eprintln};

// --- Mimariye Özgü ELF Relocation Tipleri (Örnekler) ---
// Bu sadece bir başlangıç. Her mimarinin yüzlerce relocation tipi olabilir.

// AArch64 Relocation Tipleri (Örnekler, tam liste değil)
const R_AARCH64_ABS64: u32 = 257;   // Absolute 64-bit address
const R_AARCH64_CALL26: u32 = 283;  // PC-relative call/branch (26-bit immediate)
const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275; // ADR/ADRP instruction (Page-relative)
const R_AARCH64_ADD_ABS_LO12_NC: u32 = 276; // ADD instruction (Low 12-bit of absolute address)

// RISC-V Relocation Tipleri (Örnekler, tam liste değil)
const R_RISCV_32: u32 = 1;        // Absolute 32-bit (for 32-bit values)
const R_RISCV_64: u32 = 2;        // Absolute 64-bit (for 64-bit values)
const R_RISCV_BRANCH: u32 = 16;   // PC-relative branch (for branches)
const R_RISCV_JAL: u32 = 17;      // PC-relative JAL (Jump and Link)
const R_RISCV_CALL: u32 = 18;     // PC-relative Call (AUIPC + JALR)
const R_RISCV_GOT_HI20: u32 = 21; // GOT (Global Offset Table) entry (high 20 bits)
const R_RISCV_PCREL_HI20: u32 = 23; // PC-relative (high 20 bits)
const R_RISCV_PCREL_LO12_I: u32 = 24; // PC-relative (low 12 bits, I-type)

// x86-64 Relocation Tipleri (Örnekler, tam liste değil)
const R_X86_64_64: u32 = 1;      // Absolute 64-bit
const R_X86_64_PC32: u32 = 2;    // PC-relative 32-bit
const R_X86_64_PLT32: u32 = 4;   // PC-relative 32-bit for PLT entry
const R_X86_64_GOTPCREL: u32 = 9; // PC-relative 32-bit for GOT

// MIPS64 Relocation Tipleri (Örnekler, tam liste değil)
const R_MIPS_64: u32 = 5;         // Absolute 64-bit
const R_MIPS_JUMP_SLOT: u32 = 127; // For Jump slot (PLT)
const R_MIPS_REL32: u32 = 26;     // PC-relative 32-bit

/// Relocation işlemini yürüten yapı.
pub struct Relocator<'a> {
    // SymbolResolver'dan gelen çözümlenmiş sembolleri kullanabilmek için referans tutarız.
    // Relocator'ın SymbolResolver'dan sonra çağrılması gerektiğini belirtir.
    resolved_symbols_map: &'a HashMap<String, ResolvedSymbol>,
    // Common sembollerin nihai adresleri için (eğer SymbolResolver'da belirlenmediyse)
    common_symbols_map: &'a HashMap<String, ResolvedSymbol>,
}

impl<'a> Relocator<'a> {
    pub fn new(resolved_symbols: &'a HashMap<String, ResolvedSymbol>, common_symbols: &'a HashMap<String, ResolvedSymbol>) -> Self {
        Relocator {
            resolved_symbols_map: resolved_symbols,
            common_symbols_map: common_symbols,
        }
    }

    /// Object dosyalarındaki tüm yeniden konumlandırma girişlerini uygular.
    /// Bu işlemden önce sembollerin çözümlenmiş olması gerekir.
    pub fn apply_relocations(&mut self, object_files: &mut Vec<ObjectFile>, config: &LinkerConfig) -> Result<()> {
        println!("INFO: Yeniden konumlandırmalar uygulanıyor...");

        // Tüm object dosyalarındaki bölümlerin nihai sanal adreslerini belirle.
        // Bu, .laxe betiğindeki SECTIONS komutlarına göre yapılmalı.
        // Şimdilik basit bir sıralama ve ardışık yerleştirme varsayalım.
        // Gerçekte, linker betiği bu kısmı çok daha detaylı kontrol eder.
        let mut current_virtual_address: u64 = 0x10000; // Varsayılan başlangıç adresi
        let mut section_start_addresses: HashMap<(usize, u16), u64> = HashMap::new(); // (obj_idx, section_idx) -> final_addr

        // Önce common semboller için alan ayır (genellikle .bss'in sonunda)
        for (sym_name, resolved_sym) in self.common_symbols_map.iter() {
            // Hizalama ihtiyacını dikkate al
            let alignment = 8; // Varsayılan 8 bayt hizalama (64-bit mimariler için)
            current_virtual_address = (current_virtual_address + alignment - 1) / alignment * alignment;
            
            // resolved_sym'in final_address'ini güncelle
            // Bu, SymbolResolver'daki ortak semboller için de güncellenmeliydi,
            // ancak şimdilik burada yapıyoruz.
            // Bu kısım, SymbolResolver ile Relocator arasındaki etkileşimde revize edilebilir.
            // SymbolResolver'ın `common_symbols_map`'indeki ResolvedSymbol'lar mutasyona uğratılamaz.
            // Dolayısıyla bu adres bilgisi, ObjectFile içindeki sembollere yansıtılmalı.
            println!("DEBUG: Ortak sembol '{}' için 0x{:x} adresi ayrıldı, boyut: 0x{:x}",
                     sym_name, current_virtual_address, resolved_sym.size);
            
            // Eğer object_files içindeki ilgili ElfSymbol'ü güncelleyebilirsek, iyi olur.
            // Aksi halde, SymbolResolver'ın döndürdüğü `resolved_symbols_map`'i mutable yapmamız gerekir.
            // Şimdilik, burada hesaplanan adresi sadece relocate ederken kullanacağız.
            current_virtual_address += resolved_sym.size;
        }

        // Program bölümlerini .laxe betiğindeki sıraya göre yerleştir
        // Bu bölüm, linker_config.sections'ı ve object_files.sections'ı bağlamalıdır.
        // Bu kısım, karmaşık bir algoritmaya sahiptir ve genellikle bir 'layout' fazı gerektirir.
        // Şimdilik, object dosyalarındaki bölümleri basitçe ardışık olarak yerleştirelim.
        // Daha sonra, bu kısmı .laxe betiğindeki `SECTIONS` komutlarına göre güncelleyeceğiz.

        // Basit Yerleştirme (geçici): Tüm object dosyalarındaki PROGBITS bölümlerini art arda yerleştir.
        // Gerçek bir linker'da bu, .laxe betiğindeki bölüm düzenine göre yapılmalıdır.
        let mut overall_section_data: HashMap<String, Vec<u8>> = HashMap::new(); // Tüm bölümlerin birleşmiş verisi
        let mut overall_section_addr: HashMap<String, u64> = HashMap::new(); // Birleşmiş bölümlerin başlangıç adresleri

        // .laxe betiğinde tanımlanan bölümleri öncelikli olarak işle
        for linker_section_config in config.sections.iter() {
            // current_virtual_address'ı linker_section_config.address'e veya hizalamaya göre güncelle
            if let Some(fixed_addr) = linker_section_config.address {
                current_virtual_address = fixed_addr;
            } else if let Some(align) = linker_section_config.align {
                 if align > 0 {
                    current_virtual_address = (current_virtual_address + align - 1) / align * align;
                }
            }

            overall_section_addr.insert(linker_section_config.name.clone(), current_virtual_address);
            println!("DEBUG: {} bölümü için başlangıç adresi belirlendi: 0x{:x}", linker_section_config.name, current_virtual_address);

            // Bu bölüme ait tüm object dosyalarındaki verileri topla
            for (obj_idx, obj_file) in object_files.iter_mut().enumerate() {
                for obj_section in obj_file.sections.iter_mut() {
                    if obj_section.section_type == SHT_PROGBITS || obj_section.section_type == SHT_NOBITS {
                        if obj_section.name == linker_section_config.name {
                            // Bölümün veri boyutunu current_virtual_address'a ekle
                            // Burası çok önemli: Sembol offsetleri bu base adrese göre hesaplanmalı
                            // ve ElfSymbol.value güncellenmelidir.
                            let actual_section_data_size = if obj_section.section_type == SHT_NOBITS { 0 } else { obj_section.data.len() as u64 };
                            section_start_addresses.insert((obj_idx, obj_section.index as u16), current_virtual_address);

                            // Sembollerin value (offset) alanlarını bu section'ın global adresine göre güncelle.
                            for sym in obj_file.symbols.iter_mut() {
                                if sym.shndx == obj_section.index as u16 {
                                    sym.value += current_virtual_address;
                                }
                            }

                            // Birleşmiş veri vektörünü doldur (eğer SHT_PROGBITS ise)
                            if let Some(ref mut existing_data) = overall_section_data.get_mut(&linker_section_config.name) {
                                existing_data.extend_from_slice(&obj_section.data);
                            } else {
                                overall_section_data.insert(linker_section_config.name.clone(), obj_section.data.clone());
                            }
                            
                            current_virtual_address += actual_section_data_size;
                            // println!("DEBUG: Bölüm '{}' (obj {}): final_addr = 0x{:x} (boyut: 0x{:x})",
                            //          obj_section.name, obj_idx, section_start_addresses.get(&(obj_idx, obj_section.index as u16)).unwrap(), obj_section.size);
                        }
                    }
                }
            }
        }

        // Şimdi relocations'ı uygula
        for (obj_idx, obj_file) in object_files.iter_mut().enumerate() {
            for relocation in obj_file.relocations.iter() {
                // Relocation'ın ait olduğu bölümün indeksini bul
                // Genellikle relocation bölümü, ilgili kod/veri bölümünün "link" veya "info" alanında belirtilir.
                // Basitlik için, relocation'ın hedeflediği bölümü bulmamız gerekiyor.
                // Bu, ElfRelocation.info'dan gelen sembolün ilişkili olduğu bölüm veya doğrudan .rela.text'in uygulandığı .text gibi.
                let mut target_section_index: Option<u16> = None;
                let target_symbol = self.resolved_symbols_map.get(
                    &obj_file.symbols[relocation.symbol_index as usize].name
                );

                if let Some(sym) = target_symbol {
                    target_section_index = Some(sym.section_idx);
                }
                
                let target_section_base_addr = if let Some(sec_idx) = target_section_index {
                    *section_start_addresses.get(&(obj_idx, sec_idx)).unwrap_or(&0) // Bölümün nihai başlangıç adresi
                } else {
                    0 // Tanımsız sembol için sıfır (dinamik bağlamada çalışma zamanında çözülür)
                };

                let target_section_data = &mut obj_file.sections
                                                        .iter_mut()
                                                        .find(|s| s.section_type == SHT_PROGBITS && relocation.offset >= s.offset && relocation.offset < s.offset + s.size)
                                                        .map(|s| &mut s.data)
                                                        .ok_or_else(|| LinkerError::Relocation(RelocationError::TargetSectionNotFound(
                                                            String::from_format_args!("Hedef bölüm bulunamadı: obj={}, relocation_offset=0x{:x}", obj_file.filename, relocation.offset)
                                                        )))?;

                // Relocation offset'ini bölümün içindeki ham veri offsetine çevir
                let rel_offset_in_section_data = relocation.offset as usize - obj_file.sections
                                                    .iter()
                                                    .find(|s| s.section_type == SHT_PROGBITS && relocation.offset >= s.offset && relocation.offset < s.offset + s.size)
                                                    .map(|s| s.offset).unwrap_or(0) as usize;
                
                Self::apply_single_relocation(
                    relocation,
                    target_section_data, // Bu bölümün verisi
                    &obj_file.elf_header.machine, // Mimari bilgisi
                    target_symbol, // Çözümlenmiş hedef sembol
                    target_section_base_addr, // Hedef bölümün nihai başlangıç adresi
                    rel_offset_in_section_data, // Relocation'ın bölüm verisi içindeki offseti
                )?;
            }
        }

        println!("INFO: Yeniden konumlandırmalar başarıyla uygulandı.");
        Ok(())
    }

    /// Tek bir yeniden konumlandırma girdisini uygular.
    fn apply_single_relocation(
        relocation: &ElfRelocation,
        section_data: &mut Vec<u8>,
        machine: &u16,
        target_symbol: Option<&'a ResolvedSymbol>,
        target_section_base_addr: u64,
        rel_offset_in_section_data: usize, // relocation offset'in bölüm verisi içindeki konumu
    ) -> Result<()> {
        let sym_val: u64 = target_symbol.map_or(0, |s| s.final_address);
        let addend = relocation.addend;
        let pc_addr = target_section_base_addr + rel_offset_in_section_data as u64; // PC'nin mevcut adresi (relocation'ın uygulandığı yer)

        match machine {
            EM_X86_64 => {
                match relocation.typ {
                    R_X86_64_64 => {
                        // Mutlak 64-bit adres
                        let val = sym_val.wrapping_add(addend as u64);
                        section_data[rel_offset_in_section_data..rel_offset_in_section_data + 8].copy_from_slice(&val.to_le_bytes());
                    },
                    R_X86_64_PC32 | R_X86_64_PLT32 | R_X86_64_GOTPCREL => {
                        // PC-relative 32-bit adres
                        // S = sembolün değeri (sym_val)
                        // A = addend
                        // P = relocation'ın uygulandığı yerin adresi (pc_addr)
                        let val = (sym_val.wrapping_add(addend as u64)).wrapping_sub(pc_addr) as u32;
                        section_data[rel_offset_in_section_data..rel_offset_in_section_data + 4].copy_from_slice(&val.to_le_bytes());
                    },
                    _ => {
                        eprintln!("UYARI: Desteklenmeyen x86-64 relocation tipi: {} (offset: 0x{:x})", relocation.typ, relocation.offset);
                        // Hata döndür veya göz ardı et
                    }
                }
            },
            EM_AARCH64 => {
                match relocation.typ {
                    R_AARCH64_ABS64 => {
                         let val = sym_val.wrapping_add(addend as u64);
                         section_data[rel_offset_in_section_data..rel_offset_in_section_data + 8].copy_from_slice(&val.to_le_bytes());
                    },
                    R_AARCH64_CALL26 => {
                        // PC-relative 26-bit çağrı/dallanma
                        // (S + A - P) / 4
                        let offset = (sym_val.wrapping_add(addend as u64)).wrapping_sub(pc_addr);
                        if offset % 4 != 0 {
                            return Err(LinkerError::Relocation(RelocationError::UnalignedRelocation(
                                String::from_format_args!("AArch64 R_AARCH64_CALL26 hizalama hatası: 0x{:x}", offset)
                            )));
                        }
                        let encoded_offset = (offset / 4) as u32; // 26-bit immediate
                        let inst = u32::from_le_bytes(section_data[rel_offset_in_section_data..rel_offset_in_section_data + 4].try_into().unwrap());
                        let new_inst = (inst & 0xFC000000) | (encoded_offset & 0x03FFFFFF); // Sadece immediate alanını güncelle
                        section_data[rel_offset_in_section_data..rel_offset_in_section_data + 4].copy_from_slice(&new_inst.to_le_bytes());
                    },
                    // Diğer AArch64 relocation tipleri buraya eklenecek
                    _ => {
                        eprintln!("UYARI: Desteklenmeyen AArch64 relocation tipi: {} (offset: 0x{:x})", relocation.typ, relocation.offset);
                    }
                }
            },
            EM_RISCV => {
                match relocation.typ {
                    R_RISCV_64 => {
                        let val = sym_val.wrapping_add(addend as u64);
                        section_data[rel_offset_in_section_data..rel_offset_in_section_data + 8].copy_from_slice(&val.to_le_bytes());
                    },
                    R_RISCV_JAL => {
                        // JAL instruksiyonu için PC-relative offset (20-bit immediate)
                        let offset = (sym_val.wrapping_add(addend as u64)).wrapping_sub(pc_addr);
                        if offset % 2 != 0 {
                            return Err(LinkerError::Relocation(RelocationError::UnalignedRelocation(
                                String::from_format_args!("RISC-V R_RISCV_JAL hizalama hatası: 0x{:x}", offset)
                            )));
                        }
                        // RISC-V J-type instruksiyonu için offset kodlama
                        // Bu kısım çok karmaşıktır ve RISC-V ISA'sına göre detaylı implementasyon gerektirir.
                        // Şimdilik sadece bir yer tutucu.
                        let encoded_offset = Self::encode_riscv_j_type_offset(offset as i64)?;
                        let inst = u32::from_le_bytes(section_data[rel_offset_in_section_data..rel_offset_in_section_data + 4].try_into().unwrap());
                        let new_inst = (inst & 0xFFF00000) | (encoded_offset & 0x000FFFFF); // Sadece immediate alanını güncelle
                        section_data[rel_offset_in_section_data..rel_offset_in_section_data + 4].copy_from_slice(&new_inst.to_le_bytes());
                    },
                    R_RISCV_CALL => {
                        // AUIPC + JALR çifti için relocation. İki instruksiyonu etkiler.
                        // Bu, iki instruction'ı birden değiştirmeyi gerektirir.
                        // Çok daha karmaşık bir relocation tipi.
                        // Şimdilik sadece bilgilendirme.
                        eprintln!("UYARI: RISC-V R_RISCV_CALL relocation tipi çok karmaşık, basit implementasyonla yetinilemez.");
                         return Err(LinkerError::Relocation(RelocationError::UnsupportedRelocationType(
                            String::from_format_args!("RISC-V R_RISCV_CALL desteklenmiyor.")
                        )));
                    },
                    // Diğer RISC-V relocation tipleri buraya eklenecek
                    _ => {
                        eprintln!("UYARI: Desteklenmeyen RISC-V relocation tipi: {} (offset: 0x{:x})", relocation.typ, relocation.offset);
                    }
                }
            },
            EM_MIPS => {
                match relocation.typ {
                    R_MIPS_64 => {
                         let val = sym_val.wrapping_add(addend as u64);
                         section_data[rel_offset_in_section_data..rel_offset_in_section_data + 8].copy_from_slice(&val.to_le_bytes());
                    },
                    // MIPS'in relocationları genellikle dallanma gecikme slotları ve farklı adresleme modları nedeniyle
                    // diğer mimarilerden daha karmaşıktır.
                    // Örneğin, R_MIPS_26, R_MIPS_HI16/LO16 çiftleri.
                    _ => {
                        eprintln!("UYARI: Desteklenmeyen MIPS64 relocation tipi: {} (offset: 0x{:x})", relocation.typ, relocation.offset);
                    }
                }
            },
            // Diğer mimariler buraya eklenecek (OpenRISC, PowerPC64, LoongArch64, Elbrus, SPARC64)
            _ => {
                return Err(LinkerError::Relocation(RelocationError::UnsupportedArchitecture(
                    String::from_format_args!("Desteklenmeyen mimari için yeniden konumlandırma: {}", machine)
                )));
            }
        }
        Ok(())
    }

    // RISC-V J-type instruksiyonu için 20-bit offset'i kodlama yardımcı fonksiyonu.
    // Bu kodlama çok özeldir ve RISC-V spesifikasyonlarına göre yapılmalıdır.
    // Aşağıdaki implementasyon basitleştirilmiştir ve tam doğru olmayabilir.
    fn encode_riscv_j_type_offset(offset: i64) -> Result<u32> {
        // Offset 2'ye bölünmeli
        let offset_div_2 = offset / 2;
        if offset_div_2 < -(1 << 19) || offset_div_2 >= (1 << 19) {
            return Err(LinkerError::Relocation(RelocationError::ValueOutOfRange(
                String::from_format_args!("RISC-V J-type offset aralığı dışında: 0x{:x}", offset)
            )));
        }

        // 20-bit offset'i J-type instruksiyon formatına göre düzenle:
        // imm[20|10:1|11|19:12]
        // 1. bit (sign): imm[20]
        // 11 bit: imm[10:1]
        // 1 bit: imm[11]
        // 8 bit: imm[19:12]
        let imm_20 = ((offset_div_2 >> 19) & 0x1) as u32;
        let imm_10_1 = ((offset_div_2 >> 1) & 0x3FF) as u32;
        let imm_11 = ((offset_div_2 >> 10) & 0x1) as u32;
        let imm_19_12 = ((offset_div_2 >> 11) & 0xFF) as u32;

        let encoded = (imm_20 << 20) | (imm_10_1 << 1) | (imm_11 << 11) | (imm_19_12 << 12);
        Ok(encoded)
    }
}
