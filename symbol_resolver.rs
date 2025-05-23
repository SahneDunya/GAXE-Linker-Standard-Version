// symbol_resolver.rs
#![no_std]

use crate::linker_config::{LinkerConfig, BindingType};
use crate::object_parser::{ObjectFile, ElfSymbol, ElfSection, SHT_NOBITS, SHT_PROGBITS, SHT_STRTAB};
use crate::error::{LinkerError, Result, SymbolResolutionError};
use sahne64::utils::{String, Vec, HashMap};
use sahne64::{print, println, eprintln};

// ELF Sembol Bağlama Tipleri (st_info >> 4)
const STB_LOCAL: u8 = 0;   // Local symbol
const STB_GLOBAL: u8 = 1;  // Global symbol
const STB_WEAK: u8 = 2;    // Weak symbol

// ELF Sembol Tipleri (st_info & 0x0F)
const STT_NOTYPE: u8 = 0;   // No type
const STT_OBJECT: u8 = 1;   // Data object
const STT_FUNC: u8 = 2;     // Function
const STT_SECTION: u8 = 3;  // Section
const STT_FILE: u8 = 4;     // File

// ELF Özel Section Header Index (shndx)
const SHN_UNDEF: u16 = 0;   // Undefined symbol
const SHN_ABS: u16 = 0xFFF1; // Absolute symbol (value is fixed)
const SHN_COMMON: u16 = 0xFFF2; // Common symbol (uninitialized data)

/// Çözümlenmiş bir sembolün nihai konumu ve ait olduğu ObjectFile.
#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub name: String,         // Sembolün adı
    pub final_address: u64,   // Sembolün bellekteki nihai sanal adresi
    pub size: u64,            // Sembolün boyutu
    pub is_defined: bool,     // Sembol tanımlanmış mı (SHN_UNDEF değil mi)
    pub object_file_idx: usize, // Bu sembolü tanımlayan ObjectFile'ın indeksi
    pub elf_symbol_idx: usize, // Bu sembolün ObjectFile içindeki ElfSymbol indeksi
    pub section_idx: u16,     // Ait olduğu orijinal bölümün dizini (SHN_UNDEF olabilir)
}

/// Linker içindeki tüm sembolleri yöneten ve çözen yapı.
pub struct SymbolResolver {
    /// Tüm object dosyalarındaki global ve weak sembollerin haritası.
    /// Key: Sembol adı, Value: Sembolü tanımlayan ResolvedSymbol.
    pub global_symbols: HashMap<String, ResolvedSymbol>,
    /// Ortak (COMMON) sembollerin (başlatılmamış veriler) yönetimi.
    /// Common semboller daha sonra .bss gibi bir bölüme yerleştirilir.
    pub common_symbols: HashMap<String, ResolvedSymbol>,
    /// Dinamik bağlama için dışa aktarılmış (exported) semboller.
    pub exported_symbols: HashMap<String, ResolvedSymbol>,
}

impl SymbolResolver {
    pub fn new() -> Self {
        SymbolResolver {
            global_symbols: HashMap::new(),
            common_symbols: HashMap::new(),
            exported_symbols: HashMap::new(),
        }
    }

    /// Giriş ObjectFile'larındaki tüm sembolleri toplar ve çözer.
    ///
    /// Bu fonksiyon iki ana görevi yapar:
    /// 1. Tüm global ve weak sembol tanımlarını toplar.
    /// 2. Tanımlanmamış sembol referanslarını çözer.
    pub fn resolve_symbols(&mut self, object_files: &mut Vec<ObjectFile>, config: &LinkerConfig) -> Result<()> {
        println!("INFO: Sembol çözümleme başlatılıyor...");

        // İlk Geçiş: Tüm tanımlı global, weak ve common sembolleri topla
        for (obj_idx, obj_file) in object_files.iter_mut().enumerate() {
            // Her object dosyasındaki her bölüm için, bölümün başlangıç adresini hesapla
            // Bu, sembol değerlerini (offsetlerini) nihai sanal adreslere çevirmek için önemli.
            // Şimdilik .laxe betiğinde verilen adresleri kullanacağız.
            // Bu kısım, object dosyalarının yerleştirileceği nihai adresler belirlendiğinde daha doğru olacak.
            // Şimdilik basitçe 0 varsayalım, gerçek adresler Relocator'da güncellenecek.
            let mut section_base_addresses: HashMap<u16, u64> = HashMap::new();
            for section in obj_file.sections.iter() {
                 // Eğer bölüm .laxe betiğinde bir adrese sahipse, onu kullan.
                // Aksi halde, şimdilik 0 varsayalım.
                // Bu, daha sonra LinkerConfig'in `sections` alanındaki bilgilerle doldurulacak.
                section_base_addresses.insert(section.index as u16, 0); // Yerleşim sonra yapılacak
            }


            for (sym_idx, symbol) in obj_file.symbols.iter().enumerate() {
                let sym_binding = symbol.bind();
                let sym_type = symbol.typ();

                match sym_binding {
                    STB_GLOBAL | STB_WEAK => {
                        let is_defined = symbol.shndx != SHN_UNDEF && symbol.shndx != SHN_COMMON;
                        let mut final_address = 0; // Geçici, daha sonra relocator tarafından güncellenecek

                        if is_defined {
                            // Sembol tanımlıysa, bölümüne göre bir başlangıç adresi olsun
                            if let Some(&base_addr) = section_base_addresses.get(&symbol.shndx) {
                                final_address = base_addr + symbol.value; // value, bölüm içindeki offset
                            } else if symbol.shndx == SHN_ABS {
                                final_address = symbol.value; // Absolute semboller için değer direk adres
                            } else {
                                // Tanımlı ancak ilişkili bir bölümü olmayan semboller için hata?
                                // Ya da şimdilik 0 bırak.
                                eprintln!("UYARI: Tanımlı sembol '{}' (obj {}) ilişkili bir bölüm dizinine sahip değil (shndx: {}).", symbol.name, obj_idx, symbol.shndx);
                            }
                        }

                        let resolved_sym = ResolvedSymbol {
                            name: symbol.name.clone(),
                            final_address,
                            size: symbol.size,
                            is_defined,
                            object_file_idx: obj_idx,
                            elf_symbol_idx: sym_idx,
                            section_idx: symbol.shndx,
                        };

                        // Global ve Weak sembol çakışma kuralları
                        if sym_binding == STB_GLOBAL {
                            if self.global_symbols.contains_key(&resolved_sym.name) {
                                let existing = self.global_symbols.get(&resolved_sym.name).unwrap();
                                if existing.is_defined && resolved_sym.is_defined {
                                    // İki global sembol tanımlıysa hata
                                    return Err(LinkerError::SymbolResolution(
                                        SymbolResolutionError::MultipleDefinitions(
                                            resolved_sym.name.clone(),
                                            object_files[existing.object_file_idx].filename.clone(),
                                            object_files[resolved_sym.object_file_idx].filename.clone(),
                                        )
                                    ));
                                } else if !existing.is_defined && resolved_sym.is_defined {
                                    // Yeni sembol tanımlıysa, eskisi tanımlı değilse yeni olanı al
                                    self.global_symbols.insert(resolved_sym.name.clone(), resolved_sym);
                                }
                                // Eğer ikisi de tanımlı değilse veya existing tanımlı ise bir şey yapma.
                            } else {
                                self.global_symbols.insert(resolved_sym.name.clone(), resolved_sym);
                            }
                        } else if sym_binding == STB_WEAK { // Weak semboller
                             if self.global_symbols.contains_key(&resolved_sym.name) {
                                 let existing = self.global_symbols.get(&resolved_sym.name).unwrap();
                                 if !existing.is_defined && resolved_sym.is_defined {
                                     // Eğer global sembol yoksa veya tanımsız ise weak sembolü al
                                     self.global_symbols.insert(resolved_sym.name.clone(), resolved_sym);
                                 }
                                 // Global sembol tanımlı ise, weak sembol onu geçersiz kılamaz.
                             } else {
                                 self.global_symbols.insert(resolved_sym.name.clone(), resolved_sym);
                             }
                        }
                    },
                    _ => { /* Local semboller sadece kendi object dosyaları içinde ilgilidir. */ }
                }

                // Ortak (COMMON) sembolleri özel olarak ele al
                if symbol.shndx == SHN_COMMON {
                    // Common semboller, bellek alanı ayrılmamış başlatılmamış değişkenlerdir.
                    // Linker, bunların en büyük boyutlusunu seçer ve genellikle .bss bölümüne yerleştirir.
                    if self.common_symbols.contains_key(&symbol.name) {
                        let existing_common = self.common_symbols.get_mut(&symbol.name).unwrap();
                        if symbol.size > existing_common.size {
                            existing_common.size = symbol.size; // En büyük boyutu koru
                        }
                    } else {
                        self.common_symbols.insert(
                            symbol.name.clone(),
                            ResolvedSymbol {
                                name: symbol.name.clone(),
                                final_address: 0, // Adresleri sonra belirlenecek
                                size: symbol.size,
                                is_defined: true, // Ortak olarak tanımlanmış sayılır
                                object_file_idx: obj_idx,
                                elf_symbol_idx: sym_idx,
                                section_idx: SHN_COMMON,
                            },
                        );
                    }
                }
            }
        }

        // İkinci Geçiş: Tüm tanımlanmamış sembol referanslarını çöz
        for (obj_idx, obj_file) in object_files.iter_mut().enumerate() {
            for symbol_ref in obj_file.symbols.iter_mut() {
                if symbol_ref.shndx == SHN_UNDEF { // Tanımlanmamış sembol
                    if let Some(resolved) = self.global_symbols.get(&symbol_ref.name) {
                        if resolved.is_defined {
                            // Global semboller içinde bulundu ve tanımlı
                            // Sembol referansının değerini ve ait olduğu bölümü güncelle.
                            // Bu değerler, relocator için kullanılacak.
                            symbol_ref.value = resolved.final_address;
                            symbol_ref.shndx = resolved.section_idx;
                            println!("DEBUG: Tanımlanmamış sembol '{}' (obj {}) çözüldü: final_addr=0x{:x}",
                                     symbol_ref.name, obj_idx, resolved.final_address);
                        } else {
                            // Tanımlı olmayan global sembol (başka bir .o dosyasında tanımlanacak ama henüz tanımlanmamış)
                            // Bu durum, döngüsel bağımlılıklar veya eksik object dosyaları nedeniyle olabilir.
                            // Eğer dinamik bağlama destekleniyorsa, bu semboller dinamik kütüphanelerden gelebilir.
                            if config.binding_type == BindingType::Static {
                                return Err(LinkerError::SymbolResolution(
                                    SymbolResolutionError::UndefinedSymbol(
                                        symbol_ref.name.clone(),
                                        obj_file.filename.clone(),
                                    )
                                ));
                            } else {
                                // Dinamik bağlama ise, bu semboller dışa aktarılmalı (exported).
                                self.exported_symbols.insert(symbol_ref.name.clone(), resolved.clone());
                                println!("INFO: Tanımlanmamış sembol '{}' dinamik olarak çözülecek (obj {}).", symbol_ref.name, obj_idx);
                            }
                        }
                    } else if let Some(common_sym) = self.common_symbols.get(&symbol_ref.name) {
                        // Common sembol olarak bulundu (sadece bir tanesi geçerli)
                         symbol_ref.value = common_sym.final_address; // Adresleri sonra belirlenecek
                         symbol_ref.shndx = common_sym.section_idx;
                         println!("DEBUG: Tanımlanmamış sembol '{}' (obj {}) COMMON olarak çözüldü.", symbol_ref.name, obj_idx);
                    }
                    else {
                        // Sembol ne global/weak sembollerde ne de common sembollerde bulunamadı.
                        // Statik bağlamada bu bir hata.
                        if config.binding_type == BindingType::Static {
                            return Err(LinkerError::SymbolResolution(
                                SymbolResolutionError::UndefinedSymbol(
                                    symbol_ref.name.clone(),
                                    obj_file.filename.clone(),
                                )
                            ));
                        } else {
                            // Dinamik bağlamada, bu sembol dış bir kütüphaneden gelecektir.
                            // runtime'da çözülmesi için işaretle.
                            // exports'a ekleme.
                            println!("INFO: Tanımlanmamış sembol '{}' (obj {}) dış kütüphaneden gelecek.", symbol_ref.name, obj_idx);
                            self.exported_symbols.insert(
                                symbol_ref.name.clone(),
                                ResolvedSymbol {
                                    name: symbol_ref.name.clone(),
                                    final_address: 0, // Adres runtime'da çözülecek
                                    size: symbol_ref.size,
                                    is_defined: false, // Burada tanımlı değil
                                    object_file_idx: obj_idx,
                                    elf_symbol_idx: 0, // İlgisiz
                                    section_idx: SHN_UNDEF,
                                }
                            );
                        }
                    }
                }
            }
        }

        // Giriş noktası sembolünün varlığını ve tanımlı olup olmadığını kontrol et
        if config.entry_point_symbol != "" {
            if let Some(entry_sym) = self.global_symbols.get(&config.entry_point_symbol) {
                if !entry_sym.is_defined {
                    return Err(LinkerError::SymbolResolution(
                        SymbolResolutionError::UndefinedSymbol(
                            config.entry_point_symbol.clone(),
                            String::from_str("Giriş noktası")
                        )
                    ));
                }
            } else {
                return Err(LinkerError::SymbolResolution(
                    SymbolResolutionError::UndefinedSymbol(
                        config.entry_point_symbol.clone(),
                        String::from_str("Giriş noktası")
                    )
                ));
            }
        }

        println!("INFO: Sembol çözümleme tamamlandı.");
        Ok(())
    }

    /// Tüm çözümlenmiş sembollerin (global, weak, common) listesini döndürür.
    /// Bu, nihai çıktı dosyasına yazılacak sembol tablosunu oluşturmak için kullanılabilir.
    pub fn get_all_resolved_symbols(&self) -> Vec<ResolvedSymbol> {
        let mut all_symbols: Vec<ResolvedSymbol> = Vec::new();
        for sym in self.global_symbols.values() {
            all_symbols.push(sym.clone());
        }
        for sym in self.common_symbols.values() {
            // Common semboller zaten global_symbols'da yer almıyorsa ekle.
            // Bu kısım, linker'ın ortak sembolleri nasıl ele aldığına göre değişir.
            // Genellikle .bss'e yerleştirildikleri için ayrı yönetilebilirler.
            if !self.global_symbols.contains_key(&sym.name) {
                 all_symbols.push(sym.clone());
            }
        }
        all_symbols
    }
}
