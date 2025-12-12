nim strenc, nim malware, frida, exe

# Challenge

First, notice the use of strenc to obfuscate strings using XOR. Then we modify this [script](https://github.com/rasti37/nim-strdec-ida/blob/main/strdec.py) to suit our scenario. New script :

<details>
  <summary>New Script</summary>
  
```py
import struct, ida_hexrays, idautils
from ida_hexrays import *

IDENTIFIER = 'gkkaekgaEE'
filetype = idaapi.inf_get_filetype()
IS_ELF   = filetype == idc.FT_ELF
IS_PE    = filetype == idc.FT_PE
assert IS_ELF or IS_PE, "Only ELF and PE binaries are supported."
IS_64 = ida_ida.inf_is_64bit()
ITPs = [
    ITP_SEMI, ITP_COLON, ITP_CURLY1, ITP_CURLY2, ITP_BLOCK1, ITP_BLOCK2, ITP_ARG64, ITP_CASE, ITP_DO, ITP_ELSE, ITP_SIGN, ITP_BRACE1, ITP_BRACE2, ITP_INNER_LAST
]

DEBUG = False  # Set to True to enable debug output

def strdecrypt(enc, key):
    l = len(enc)
    dec = list(enc)
    for i in range(l):
        for f in [0, 8, 16, 24]:
            dec[i] = (dec[i] & 0xff) ^ ((key >> f) & 0xff)
        dec[i] = bytes([dec[i]])
        key = (key + 1) & 0xffffffff
    try:
        return b''.join(dec).decode()
    except:
        return None

def get_previous_instruction(insn):
    ea = idaapi.prev_head(insn, 0)
    if ea == idaapi.BADADDR:
        return None
    return ea

def extract_word(addr):
    f = idaapi.get_qword if IS_64 else idaapi.get_dword
    return f(addr)
    
def is_valid_ptr(ptr):
    return bool(idc.get_segm_name(ptr))

def extract_key_and_encstr(xref):
    """Extract the encryption key and encrypted string from a call site."""
    if not idaapi.decode_insn(idaapi.insn_t(), xref):
        print(f"[-] Something went wrong with decoding instruction @ 0x{xref:x}")
        return None, None
    
    # Walk backwards from the call to find:
    # 1. movups xmm, cs:TM__XXX  <- encrypted string structure address
    # 2. mov r8d, key            <- immediate key value
    
    enc_string_ptr = None
    key = None
    
    ea = xref
    max_lookback = 30
    
    if DEBUG:
        print(f"\n[DEBUG] Analyzing call @ 0x{xref:x}")
    
    for i in range(max_lookback):
        ea = get_previous_instruction(ea)
        if ea is None:
            break
        
        mnem = print_insn_mnem(ea).lower()
        
        # Look for movups xmm, cs:address (loading encrypted string structure)
        if mnem == 'movups':
            op0_type = get_operand_type(ea, 0)
            op1_type = get_operand_type(ea, 1)
            
            # movups xmm, cs:XXX (loading data from memory to XMM)
            if op0_type == ida_ua.o_reg and 'xmm' in print_operand(ea, 0).lower():
                if op1_type == ida_ua.o_mem:  # Memory reference
                    src_addr = get_operand_value(ea, 1)
                    if is_valid_ptr(src_addr):
                        enc_string_ptr = src_addr
                        if DEBUG:
                            print(f"[DEBUG] Found movups at 0x{ea:x}: {print_operand(ea, 0)} <- cs:0x{src_addr:x}")
        
        # Look for mov r8d, immediate (the key)
        elif mnem == 'mov':
            op0 = print_operand(ea, 0).lower()
            op1_type = get_operand_type(ea, 1)
            
            # Check if destination is r8, r8d, or r8w
            if op0 in ['r8', 'r8d', 'r8w']:
                if op1_type == ida_ua.o_imm:  # Immediate value
                    key = get_operand_value(ea, 1)
                    if DEBUG:
                        print(f"[DEBUG] Found key at 0x{ea:x}: {op0} = 0x{key:x}")
        
        # Stop if we found both
        if enc_string_ptr is not None and key is not None:
            break
    
    if key is None or enc_string_ptr is None:
        if DEBUG:
            print(f"[DEBUG] Failed: key={key}, enc_string_ptr={enc_string_ptr}")
        return None, None
    
    # Now extract the encrypted string from the struct
    off = 0x08 if IS_64 else 0x04
    
    try:
        enc_str_length = extract_word(enc_string_ptr)
        if DEBUG:
            print(f"[DEBUG] String length at 0x{enc_string_ptr:x}: {enc_str_length}")
        
        # Sanity check on length
        if enc_str_length <= 0 or enc_str_length > 10000:
            if DEBUG:
                print(f"[DEBUG] Invalid length: {enc_str_length}")
            return None, None
        
        enc_str_object_ptr = extract_word(enc_string_ptr + off)
        
        if DEBUG:
            print(f"[DEBUG] Pointer at 0x{enc_string_ptr + off:x}: 0x{enc_str_object_ptr:x}, valid={is_valid_ptr(enc_str_object_ptr)}")
        
        if is_valid_ptr(enc_str_object_ptr):
            # The string data starts at offset +8 from the object pointer
            # This is because Nim strings have an 8-byte header (capacity/refcount)
            enc_str = idaapi.get_bytes(enc_str_object_ptr + 8, enc_str_length)
            if DEBUG:
                print(f"[DEBUG] Read {len(enc_str)} bytes from 0x{enc_str_object_ptr + 8:x} (ptr+8)")
                print(f"[DEBUG] First 16 bytes: {enc_str[:min(16, len(enc_str))].hex()}")
        else:
            # Inline string: Length | Data (no pointer, data is inline after length)
            enc_str = idaapi.get_bytes(enc_string_ptr + off, enc_str_length)
            if DEBUG:
                print(f"[DEBUG] Read {len(enc_str)} bytes inline from 0x{enc_string_ptr + off:x}")
                print(f"[DEBUG] First 16 bytes: {enc_str[:min(16, len(enc_str))].hex()}")
        
        return enc_str, key
    except Exception as e:
        if DEBUG:
            print(f"[DEBUG] Exception while extracting: {e}")
            import traceback
            traceback.print_exc()
        return None, None

def set_decrypted_string_as_comment(addr, comm):
    try:
        func_decomp = ida_hexrays.decompile(addr)
        
        tloc = ida_hexrays.treeloc_t()
        tloc.ea = addr
        
        # bruteforce ITP since ITP_SEMI, ITP_COLON fail most of the times
        for itp in ITPs:
            tloc.itp = itp
            func_decomp.set_user_cmt(tloc, comm.strip())
            idc.set_cmt(addr, comm.strip(), True)
            func_decomp.save_user_cmts()
            func_decomp.__str__()
            if not func_decomp.has_orphan_cmts():
                break
            func_decomp.del_orphan_cmts()
        else:
            idc.set_cmt(addr, comm.strip(), True)
    except:
        idc.set_cmt(addr, comm.strip(), True)

def main():
    symbols = list(idautils.Functions())
    print(f'[+] Loaded {len(symbols)} symbols')

    strenc_symbol = next(filter(lambda f: IDENTIFIER in idaapi.get_name(f), symbols), None)

    if not strenc_symbol:
        print(f'[-] The strenc function could not be found. Make sure its name contains "{IDENTIFIER}".')
        return

    xrefs = [
        x.frm for x in idautils.XrefsTo(strenc_symbol)
        if idaapi.getseg(x.frm) == idaapi.getseg(strenc_symbol)
    ]

    print(f'[+] Found {len(xrefs)} references to {idaapi.get_name(strenc_symbol)}')

    success_count = 0
    failed_xrefs = []
    
    for i, xref in enumerate(xrefs):
        enc, key = extract_key_and_encstr(xref)
        if not (enc and key):
            print(f'[-] Failed to extract enc string or key @ 0x{xref:x}')
            failed_xrefs.append(xref)
            continue
        
        dec = strdecrypt(enc, key)
        if not dec:
            print(f'[-] Failed to decrypt @ 0x{xref:x} (key=0x{key:x}, len={len(enc)})')
            if DEBUG and enc:
                print(f'[DEBUG] Encrypted bytes: {enc[:min(32, len(enc))].hex()}')
            failed_xrefs.append(xref)
            continue
        
        set_decrypted_string_as_comment(xref, dec)
        success_count += 1
        print(f'[{i+1}/{len(xrefs)}] SUCCESS @ 0x{xref:x}: {repr(dec)}')
    
    print(f'\n[+] Successfully decrypted {success_count}/{len(xrefs)} strings')
    
    if failed_xrefs and not DEBUG:
        print(f'\n[!] {len(failed_xrefs)} strings failed. Set DEBUG=True and re-run to see details for these addresses:')
        for addr in failed_xrefs[:5]:  # Show first 5
            print(f'    0x{addr:x}')
        if len(failed_xrefs) > 5:
            print(f'    ... and {len(failed_xrefs) - 5} more')

if __name__ == '__main__':
    main()
```

</details>

<img width="1852" height="539" alt="image" src="https://github.com/user-attachments/assets/e9d6bbe2-b56a-49ad-8693-1091ba62b182" />

# Encryption algorithm

```py
encrypted_byte = 0x30
key = 0x7FA405A0

# Extract each byte from the 32-bit key:
byte0 = (key)       & 0xFF  # 0xA0 (bits 0-7)
byte1 = (key >> 8)  & 0xFF  # 0x05 (bits 8-15)
byte2 = (key >> 16) & 0xFF  # 0xA4 (bits 16-23)
byte3 = (key >> 24) & 0xFF  # 0x7F (bits 24-31)

# Now XOR the encrypted byte with each of these, sequentially:
result = encrypted_byte
result = result ^ byte0  # 0x30 ^ 0xA0 = 0x90
result = result ^ byte1  # 0x90 ^ 0x05 = 0x95
result = result ^ byte2  # 0x95 ^ 0xA4 = 0x31
result = result ^ byte3  # 0x31 ^ 0x7F = 0x4E

# Final result: 0x4E (which is 'N' in ASCII)
```

1 byte of ur cipher is XOR with each byte of the 4 byte key.

```
Byte 0 uses key 0x7FA405A0
Byte 1 uses key 0x7FA405A1
Byte 2 uses key 0x7FA405A2
```

Then, the key is incremented by 1

## Nim String Data Structure

```c
typedef struct NimString {
    uint64_t length;        // Current length of the string in bytes
    NimStringData* dataPtr; // Pointer to the actual string data (or NULL for inline)
} NimString;

typedef struct NimStringData {
    uint32_t capacity;      // Maximum capacity of the string buffer
    uint32_t refcount;      // Reference count for memory management
    uint8_t data[];         // Flexible array member - actual string bytes start here
} NimStringData;
```

It looks something like this

<img width="893" height="408" alt="image" src="https://github.com/user-attachments/assets/72b294ba-b5a0-4933-82e6-271907bcb63e" />

# Reversing

1. The program checks for debugger presence
2. Checks if PeanutButter.bin exists
3. Goes through all files until first .png file is found
4. Encrypts that file

We can solve this dynamically using Frida

**Function**: `init__66read83hell_u1088` (Address: 0x14000dcf0)

**Purpose**: Initializes AES-256 in CTR mode with key and IV

**Function signature**:
```c
_BYTE *__fastcall init__66read83hell_u1088(
    __int64 context,   // RCX - AES context structure
    __int64 keyptr,    // RDX - Pointer to 32-byte key
    __int64 keylen,    // R8  - Key length (32 for AES-256)
    __int64 ivptr,     // R9  - Pointer to 16-byte IV
    __int64 ivlen      // Stack - IV length (16 bytes)
)
```

# Frida Script

Attach to init at 0xdcf0

```js
/*
 * Frida script to capture AES-256 key and IV from BreadShell
 * Hooks the AES initialization function to extract runtime values
 */

console.log("[*] BreadShell AES Key Capture Hook");
console.log("[*] Targeting: init__66read83hell_u1088");

// Get base address of BreadShell.exe
var baseAddr = Module.findBaseAddress("BreadShell.exe");
console.log("[*] BreadShell.exe base: " + baseAddr);

// Calculate absolute address of AES init function
// RVA from IDA: 0xdcf0
var aesInitAddr = baseAddr.add(0xdcf0);
console.log("[*] AES init address: " + aesInitAddr);

console.log("\n[*] Installing hook...");

Interceptor.attach(aesInitAddr, {
    onEnter: function(args) {
        try {
            console.log("\n" + "=".repeat(70));
            console.log("[*] AES-256-CTR Initialization Called");
            console.log("=".repeat(70));

            // Windows x64 fastcall convention:
            // RCX = args[0] = context
            // RDX = args[1] = key pointer
            // R8  = args[2] = key length
            // R9  = args[3] = IV pointer
            // Stack+0x28 = ivlen (5th parameter)

            var context = args[0];    
            var keyPtr  = args[1];    
            var keyLen  = args[2].toInt32();
            var ivPtr   = args[3]; 

            // Read 5th parameter from stack (x64 Windows calling convention)
            // var ivLen = Memory.readU64(this.context.rsp.add(0x28)).toInt32();

            console.log("[+] Context: " + context);
            console.log("[+] Key length: " + keyLen + " bytes");
            // console.log("[+] IV length: " + ivLen + " bytes");

            // Extract and display AES-256 key
            if (keyLen === 32) {
                console.log("\n[+] AES-256 KEY (32 bytes):");
                var keyData = keyPtr.readByteArray(keyLen);
                console.log(hexdump(keyData, { ansi: true }));

                // Also print as single hex string for easy copying
                var keyHex = "";
                var keyBytes = new Uint8Array(keyData);
                for (var i = 0; i < keyBytes.length; i++) {
                    keyHex += ("0" + keyBytes[i].toString(16)).slice(-2);
                }
                console.log("\n[KEY_HEX] " + keyHex);
            }

            // Extract and display IV

            console.log("\n[+] AES IV (16 bytes):");
            var ivData = ivPtr.readByteArray(16);
            console.log(hexdump(ivData, { ansi: true }));

            // Also print as single hex string
            var ivHex = "";
            var ivBytes = new Uint8Array(ivData);
            for (var i = 0; i < 16; i++) {
                ivHex += ("0" + ivBytes[i].toString(16)).slice(-2);
            }
            console.log("\n[IV_HEX] " + ivHex);
            

            console.log("=".repeat(70));

        } catch(e) {
            console.log("[ERROR] Exception in hook: " + e);
            console.log(e.stack);
        }
    }
});

console.log("[*] Hook installed successfully!");
console.log("[*] Waiting for BreadShell execution...\n");
```

**Captured Values**:
1. **AES Key (32 bytes)**: `9cc868e2d888afda86d7db62f9ccfc74b3a9b3462008e88dbecbf988c45702d3`
2. **IV (16 bytes)**: `ebfd0bf097cdfe16d59cf72d5b9f8dfc`
