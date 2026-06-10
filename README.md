# process-dumper

Dumps a running process to a reconstructed PE file. Reads the process image from memory, fixes section alignment, and writes a valid PE to disk.

## What it does

1. Opens a handle to the target process by PID
2. Resolves the base address of the main module via `CreateToolhelp32Snapshot`
3. Reads `SizeOfImage` from the PE header in memory
4. Dumps the full image with `ReadProcessMemory`
5. Reconstructs the PE by remapping sections from virtual alignment (`0x1000`) to file alignment (`0x200`)
6. Writes the output to disk

## PE Parser

Parses the following fields from the dumped or any PE file:

**DOS Header**
- `e_magic` (MZ signature)
- `e_lfanew`

**COFF Header**
- Machine (x86 / x64 / ARM64)
- NumberOfSections
- PointerToSymbolTable
- SizeOfOptionalHeader
- Characteristics

**Optional Header**
- Magic (PE32 / PE32+)
- AddressOfEntryPoint
- ImageBase
- SizeOfImage
- SizeOfHeaders
- Subsystem

**Section Headers**
- Name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, Characteristics

## Building

```bash
./build.sh
```

## Usage

```bash
process_dumper.exe <PID>
```

Output file: `<process_name>_dump.exe`

## Notes

- The reconstructed PE is suitable for static analysis (IDA, PE-bear, Ghidra)
- The IAT will contain resolved addresses from the original process — it is not rebuilt

# Info
https://www.sunshine2k.de/reversing/tuts/tut_pe.htm
