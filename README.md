# bn-elf-symbol-resolver

A small Binary Ninja script for quickly cleaning up ELF binaries during reverse-engineering sessions by resolving and annotating dynamic symbols.

It focuses on `.dynsym` and `.rela.plt` to recover symbol names and make otherwise stripped or partially stripped binaries easier to read.

This is not a full analysis framework—just a lightweight helper for interactive RE work when you want immediate clarity without writing a full plugin.

## What it does

- Parses ELF `.dynsym` entries
- Resolves symbol names via `.dynstr`
- Optionally ties symbols back to relocation entries (`.rela.plt`)
- Adds comments (and optionally symbols) directly in Binary Ninja at relevant addresses

The goal is to make function and data references easier to understand while stepping through a binary.

## Usage

Run the script inside Binary Ninja’s scripting console or as a snippet while analyzing an ELF binary.

Make sure the binary has been loaded and sections are available.

The script will:
1. Locate `.dynsym`, `.dynstr`, and `.rela.plt`
2. Iterate through dynamic symbols
3. Resolve names from string table offsets
4. Annotate symbol entries in the disassembly view

## Why

During reverse engineering, especially with stripped or partially stripped ELF binaries, a lot of useful context is hidden in the dynamic symbol tables.

This script is meant for quick, manual cleanup during analysis sessions—when you just want names back in the right places without spending time building a full automation pipeline.

## Notes

- Works best on standard ELF64 binaries
- Assumes presence of `.dynsym` and `.dynstr`
- Designed for quick interactive use, not batch processing
- May be extended to include PLT renaming or relocation-based function recovery
