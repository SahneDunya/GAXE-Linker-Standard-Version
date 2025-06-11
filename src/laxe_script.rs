#![no_std]

use crate::linker_config::{LinkerConfig, LinkerSection, OutputFormat};
use crate::error::{LinkerError, Result, ConfigError};
use sahne64::utils::{String, Vec, HashMap};
use sahne64::{print, println, eprintln}; // G/Ç için

/// .laxe betiğini ayrıştıran yapı.
pub struct LaxeScriptParser;

impl LaxeScriptParser {
    pub fn new() -> Self {
        LaxeScriptParser
    }

    /// Verilen .laxe betiği içeriğini ayrıştırır ve LinkerConfig'i günceller.
    pub fn parse(&self, script_content: &str, config: &mut LinkerConfig) -> Result<()> {
        let mut current_address: u64 = 0; // '.' (dot) sembolü için geçerli adres
        let mut in_sections_block = false; // SECTIONS bloğunda mıyız?

        for (line_num, line) in script_content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                // Boş satırları ve yorumları atla
                continue;
            }

            // SECTIONS bloğu dışındaki komutlar
            if !in_sections_block {
                if line.starts_with("OUTPUT_FORMAT(") && line.ends_with(")") {
                    let format_str = line["OUTPUT_FORMAT(".len()..(line.len() - 1)].trim();
                    config.output_format = Self::parse_output_format(format_str)
                        .map_err(|e| LinkerError::Config(ConfigError::InvalidValue(
                            String::from_format_args!("{} (satır {})", e.to_string(), line_num + 1)
                        )))?;
                } else if line.starts_with("ENTRY(") && line.ends_with(")") {
                    config.entry_point_symbol = String::from_str(
                        line["ENTRY(".len()..(line.len() - 1)].trim()
                    );
                } else if line.eq_ignore_ascii_case("SECTIONS") {
                    in_sections_block = true;
                    // SECTIONS bloğu açılışında `{` beklenir
                    if !line.contains('{') {
                         return Err(LinkerError::Config(ConfigError::InvalidFormat(
                            String::from_format_args!("SECTIONS bloğu açılışında '{' bekleniyor (satır {})", line_num + 1)
                        )));
                    }
                } else {
                    return Err(LinkerError::Config(ConfigError::InvalidFormat(
                        String::from_format_args!("Geçersiz komut SECTIONS bloğu dışında: {} (satır {})", line, line_num + 1)
                    )));
                }
            } else { // SECTIONS bloğu içindeki komutlar
                if line.eq_ignore_ascii_case("}") {
                    in_sections_block = false; // SECTIONS bloğunu kapat
                } else if line.starts_with(". = ") && line.ends_with(";") {
                    let addr_str = line[". = ".len()..(line.len() - 1)].trim();
                    // Adresi ayrıştırırken 0x ön eki kontrolü yap
                    if addr_str.starts_with("0x") {
                        current_address = u64::from_str_radix(&addr_str[2..], 16)
                            .map_err(|_| LinkerError::Config(ConfigError::InvalidValue(
                                String::from_format_args!("Geçersiz adres formatı: {} (satır {})", addr_str, line_num + 1)
                            )))?;
                    } else {
                        current_address = addr_str.parse::<u64>()
                            .map_err(|_| LinkerError::Config(ConfigError::InvalidValue(
                                String::from_format_args!("Geçersiz adres formatı: {} (satır {})", addr_str, line_num + 1)
                            )))?;
                    }
                } else if line.starts_with(". = ALIGN(") && line.ends_with(");") {
                    let align_str = line[". = ALIGN(".len()..(line.len() - 2)].trim();
                    let align_value = if align_str.starts_with("0x") {
                        u64::from_str_radix(&align_str[2..], 16)
                            .map_err(|_| LinkerError::Config(ConfigError::InvalidValue(
                                String::from_format_args!("Geçersiz hizalama değeri: {} (satır {})", align_str, line_num + 1)
                            )))?
                    } else {
                        align_str.parse::<u64>()
                            .map_err(|_| LinkerError::Config(ConfigError::InvalidValue(
                                String::from_format_args!("Geçersiz hizalama değeri: {} (satır {})", align_str, line_num + 1)
                            )))?
                    };
                    // current_address'ı align_value'a hizala
                    if align_value > 0 {
                        current_address = (current_address + align_value - 1) / align_value * align_value;
                    }
                }
                else if line.contains(":") && line.contains("{") && line.contains("}") {
                    // Bölüm tanımı: .text : { *(.text) }
                    let section_name_end = line.find(':').unwrap_or(line.len());
                    let section_name = line[..section_name_end].trim();

                    let mut section = LinkerSection::new(String::from_str(section_name));
                    section.address = Some(current_address); // Mevcut adresi bölümün başlangıcı olarak ayarla

                    // Şimdilik sadece bölüm adını alıyoruz, içerideki *(.text) kısmını ayrıştırmıyoruz.
                    // Gelecekte, bu kısım hangi giriş bölümlerinin buraya dahil edileceğini belirlemek için kullanılabilir.

                    // Not: Mevcut adresin bu bölümün boyutuna göre artırılması gerekir.
                    // Bu, object dosyaları okunduktan sonra Relocator veya SymbolResolver aşamasında yapılacaktır.
                    // Şimdilik sadece başlangıç adresini atıyoruz.

                    config.sections.push(section);

                    // Bu bölümün boyutunu henüz bilmediğimiz için current_address'i burada artırmıyoruz.
                    // Bu, tüm objeler parse edilip semboller çözüldükten sonra yapılacak.
                } else {
                    return Err(LinkerError::Config(ConfigError::InvalidFormat(
                        String::from_format_args!("Geçersiz komut SECTIONS bloğu içinde: {} (satır {})", line, line_num + 1)
                    )));
                }
            }
        }

        if in_sections_block {
             return Err(LinkerError::Config(ConfigError::InvalidFormat(
                String::from_format_args!("SECTIONS bloğu kapatılmadı (satır sonu).")
            )));
        }

        if !config.validate() {
            return Err(LinkerError::Config(ConfigError::InvalidConfig(
                String::from_str("Linker yapılandırması geçerli değil. Gerekli bilgiler eksik olabilir.")
            )));
        }

        Ok(())
    }

    /// String değerden OutputFormat enum'a dönüştürür.
    fn parse_output_format(s: &str) -> Result<OutputFormat> {
        match s {
            "gaxe" | "gaxe-executable" | "elf64-riscv" | "elf64-aarch64" | "elf64-x86-64" | "elf64-sparc" | "elf64-powerpc" | "elf64-loongarch" | "elf64-mips" | "elf64-elbrus" => Ok(OutputFormat::GaxeExecutable),
            "iso" | "iso-image" => Ok(OutputFormat::IsoImage),
            _ => Err(LinkerError::Config(ConfigError::InvalidValue(
                String::from_format_args!("Geçersiz çıktı formatı: {}", s)
            ))),
        }
    }
}
