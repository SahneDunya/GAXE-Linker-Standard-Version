#![no_std] // Sahne Karnal ortamında çalışabilmek için
#![feature(alloc_error_handler)] // alloc_error_handler için gerekli

// Karnal64'ün sağladığı standart olmayan kütüphaneleri ve makroları kullan
extern crate alloc; // Heap tahsisi için
use alloc::{string::String, vec::Vec};
use sahne64::{print, println, eprintln}; // Sahne Karnal'ın temel G/Ç fonksiyonları

// Kendi linker modüllerimizi içeri aktar
mod linker_config;
mod laxe_script;
mod object_parser;
mod symbol_resolver;
mod relocator;
mod output_writer;
mod error; // Hata tanımlarımız
mod utils; // Genel yardımcı fonksiyonlar

use linker_config::{LinkerConfig, BindingType, OutputFormat};
use laxe_script::LaxeScriptParser;
use object_parser::{ObjectFile, ObjectParser};
use symbol_resolver::SymbolResolver;
use relocator::Relocator;
use output_writer::OutputWriter;
use error::{LinkerError, Result}; // Linker'ın kendi hata türlerini kullan

// Bellek tahsis hatası yöneticisi (no_std ortamında gereklidir)
#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    panic!("Karnal tarafında bellek tahsis hatası: {:?}", layout);
}

/// Gaxe Linker'ın ana giriş noktası.
/// Komut satırı argümanlarını ayrıştırır ve bağlama sürecini başlatır.
#[no_mangle] // Sembolün isminin karışmasını önle
pub extern "C" fn main(argc: isize, argv: *const *const u8) -> isize {
    // Sahne Karnal'dan gelen argc ve argv'yi Rust dostu Vec<String>'e dönüştür
    let args = unsafe {
        let mut rust_args: Vec<String> = Vec::new();
        for i in 0..argc {
            let ptr = *argv.add(i as usize);
            let c_str = sahne64::utils::CStr::from_ptr(ptr as *const i8);
            rust_args.push(String::from_str(c_str.to_str().unwrap()));
        }
        rust_args
    };

    println!("Gaxe Linker başlatılıyor...");

    let mut input_object_files: Vec<String> = Vec::new();
    let mut laxe_script_path: Option<String> = None;
    let mut output_filepath: Option<String> = None;
    let mut binding_type = BindingType::Static; // Varsayılan: Statik bağlama
    let mut help_requested = false;

    // Argümanları temel düzeyde ayrıştır
    let mut i = 1; // İlk argüman program adı olduğu için 1'den başla
    while i < args.len() {
        match args[i].as_str() {
            "-o" => {
                if i + 1 < args.len() {
                    output_filepath = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("Hata: '-o' için çıktı dosyası belirtilmedi.");
                    return 1;
                }
            },
            "-l" => {
                if i + 1 < args.len() {
                    laxe_script_path = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("Hata: '-l' için linker betiği belirtilmedi.");
                    return 1;
                }
            },
            "--dynamic" => {
                binding_type = BindingType::Dynamic;
            },
            "--static" => {
                binding_type = BindingType::Static;
            },
            "--help" | "-h" => {
                help_requested = true;
                break;
            },
            arg => {
                // Diğer argümanları giriş object dosyaları olarak kabul et
                if arg.starts_with("-") {
                    eprintln!("Hata: Bilinmeyen argüman: {}", arg);
                    return 1;
                }
                input_object_files.push(arg.into());
            }
        }
        i += 1;
    }

    if help_requested || input_object_files.is_empty() || laxe_script_path.is_none() || output_filepath.is_none() {
        print_help();
        return 0;
    }

    // Linker yapılandırmasını oluştur
    let mut config = LinkerConfig::new();
    config.binding_type = binding_type;
    // Çıktı formatı, .laxe betiğinden veya varsayılan olarak belirlenecek.
    // Şimdilik varsayılan olarak .gaxe diyelim, .laxe bunu değiştirebilir.
    config.output_format = OutputFormat::GaxeExecutable;
    config.output_filepath = output_filepath.unwrap();

    // Linker betiğini oku ve yapılandırmaya uygula
    let laxe_content_result = read_file_content(laxe_script_path.unwrap().as_str());
    let laxe_content = match laxe_content_result {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Hata: Linker betik dosyası okunurken hata: {}", e);
            return 1;
        }
    };

    let laxe_parser = LaxeScriptParser::new();
    match laxe_parser.parse(&laxe_content, &mut config) {
        Ok(_) => println!("INFO: .laxe betiği başarıyla ayrıştırıldı."),
        Err(e) => {
            eprintln!("Hata: .laxe betiği ayrıştırılırken hata: {}", e);
            return 1;
        }
    }

    // Object dosyalarını ayrıştır
    let mut object_files: Vec<ObjectFile> = Vec::new();
    let object_parser = ObjectParser::new();
    for path in input_object_files.iter() {
        let obj_content_result = read_file_content(path.as_str());
        let obj_content = match obj_content_result {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Hata: Object dosyası '{}' okunurken hata: {}", path, e);
                return 1;
            }
        };
        match object_parser.parse(&obj_content) { // ObjectParser content'i byte dizisi olarak bekleyebilir
            Ok(obj_file) => object_files.push(obj_file),
            Err(e) => {
                eprintln!("Hata: Object dosyası '{}' ayrıştırılırken hata: {}", path, e);
                return 1;
            }
        }
    }
    println!("INFO: {} object dosyası başarıyla ayrıştırıldı.", object_files.len());


    // Sembolleri çöz
    let mut symbol_resolver = SymbolResolver::new();
    match symbol_resolver.resolve_symbols(&mut object_files, &config) {
        Ok(_) => println!("INFO: Semboller başarıyla çözüldü."),
        Err(e) => {
            eprintln!("Hata: Semboller çözülürken hata: {}", e);
            return 1;
        }
    }

    // Relocations'ı uygula
    let mut relocator = Relocator::new();
    match relocator.apply_relocations(&mut object_files, &config) {
        Ok(_) => println!("INFO: Yeniden konumlandırmalar başarıyla uygulandı."),
        Err(e) => {
            eprintln!("Hata: Yeniden konumlandırmalar uygulanırken hata: {}", e);
            return 1;
        }
    }

    // Çıktı dosyasını yaz
    let output_writer = OutputWriter::new();
    match output_writer.write_output(&object_files, &config) {
        Ok(_) => println!("BAŞARILI: Çıktı dosyası '{}' başarıyla oluşturuldu.", config.output_filepath),
        Err(e) => {
            eprintln!("Hata: Çıktı dosyası yazılırken hata: {}", e);
            return 1;
        }
    }

    println!("Gaxe Linker işlemi tamamlandı.");
    0 // Başarılı çıkış kodu
}

/// Konsola kullanım talimatlarını yazdırır.
fn print_help() {
    println!("Gaxe Linker Kullanımı:");
    println!("  linker [SEÇENEKLER] <giriş_dosyaları.o>...");
    println!("\nSeçenekler:");
    println!("  -o <dosya>            Çıktı dosyası adı (.gaxe veya .iso)");
    println!("  -l <betik_dosyası>    Linker betik dosyası (.laxe)");
    println!("  --dynamic             Dinamik bağlama kullan (varsayılan: statik)");
    println!("  --static              Statik bağlama kullan (açıkça belirtme)");
    println!("  -h, --help            Bu yardım mesajını göster");
    println!("\nÖrnek:");
    println!("  linker -l script.laxe -o output.gaxe main.o lib.o");
}

/// Dosya içeriğini okuma simülasyonu.
/// Sahne Karnal'da gerçek dosya sistemi API'leri ile değiştirilmelidir.
fn read_file_content(filepath: &str) -> Result<Vec<u8>> {
    // Burada Sahne Karnal'ın dosya okuma sistem çağrısı veya API'si kullanılacak.
    // Örneğin: sahne64::fs::read_file(filepath.as_bytes())?
    // Şimdilik sadece örnek bir boş byte vektörü döndürüyoruz.
    // Gerçek implementasyonda bu kısım, okunan dosyanın içeriğini byte dizisi olarak döndürmelidir.
    eprintln!("UYARI: Dosya okuma ({}): Bu bir simülasyondur. Gerçek dosya içeriği yüklenmiyor.", filepath);
    Ok(Vec::new()) // Boş içerik döndürüyoruz
}
