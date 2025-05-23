# GAXE (Sahne Karnal default executable file)
Gaxe is the standard executable file of Sahne Karnal architecture developed by Sahne Dünya. Gaxe format was developed for Sahne Karnal, an independent operating system project developed by Sahne Dünya, and this format, which is compatible with multiple operating systems thanks to being a 64-bit ELF derivative, is both open source and published under a free license. Gaxe Linker is a Linker created for this executable file. This linker is specifically designed for the Sahne Karnal Compiler compiler. If you ask why the Gaxe format is ELF-based, the Sahne Karnal independent operating system project is known for its efforts to be fully compatible with Unix, although it is not Unix-based. So it is normal that this format is based on this, but Sahne Karnal is not really a Unix! Detailed information about the Sahne Karnal Compiler compiler is described on another page, go there! I should also mention that both Gaxe Linker and Sahne Karnal Compiler use their own infrastructure, not a toolkit built on LLVM!

# Basic Fetures
1. Supported file extensions: .gaxe (main format), .elf and .iso (Gaxe Linker is specifically for files with the .gaxe extension, but it also supports other extensions!)
2. Infrastructure used by the connector: Its own infrastructure
3. Is the Gaxe executable format a 64-bit ELF derivative?: Yes
