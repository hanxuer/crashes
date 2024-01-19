### 1.The name of the affected product:
yasm 
issue: https://github.com/yasm/yasm/issues/257

### 2.The affect version
yasm v1.3.0
Commit: 9defefa

### 3.Description
yasm v1.3.0 was discovered to contain a memory leak via the function new_Token function in the modules/preprocs/nasm/nasm-pp:1512.

### 4.Vulnerability Type
memory leak

### 5.Test environment
ubuntu 18.04 TLS

### 6.Compiler yasm with asan
vendor link：https://github.com/yasm/yasm
```
$ export CC=/usr/bin/clang
$ export CXX=/usr/bin/clang++
$ ./configure --disable-shared CFLAGS="-fsanitize-recover=address -ggdb" CXXFLAGS="-fsanitize=address -ggdb" 
$ make
```

### 7.How to test
poc is in https://github.com/hanxuer/crashes/edit/main/yasm/04/poc
./yasm ./poc

### 8.ASAN report
```
=================================================================
==118137==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 45 byte(s) in 13 object(s) allocated from:
    #0 0x7fd4a61ffb40 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb40)
    #1 0x564e5f9e7fd4 in def_xmalloc libyasm/xmalloc.c:69
    #2 0x564e5fa299f5 in new_Token modules/preprocs/nasm/nasm-pp.c:1512
    #3 0x564e5fa293fb in tokenise modules/preprocs/nasm/nasm-pp.c:1425
    #4 0x564e5fa42c86 in pp_getline modules/preprocs/nasm/nasm-pp.c:5030
    #5 0x564e5fa20be0 in nasm_preproc_get_line modules/preprocs/nasm/nasm-preproc.c:195
    #6 0x564e5fa155c3 in nasm_parser_parse modules/parsers/nasm/nasm-parse.c:218
    #7 0x564e5fa140af in nasm_do_parse modules/parsers/nasm/nasm-parser.c:66
    #8 0x564e5fa14230 in nasm_parser_do_parse modules/parsers/nasm/nasm-parser.c:83
    #9 0x564e5f9ad901 in do_assemble frontends/yasm/yasm.c:519
    #10 0x564e5f9ae6bf in main frontends/yasm/yasm.c:749
    #11 0x7fd4a5d51c86 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21c86)

Direct leak of 4 byte(s) in 1 object(s) allocated from:
    #0 0x7fd4a61ffb40 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb40)
    #1 0x564e5f9e7fd4 in def_xmalloc libyasm/xmalloc.c:69
    #2 0x564e5fa299f5 in new_Token modules/preprocs/nasm/nasm-pp.c:1512
    #3 0x564e5fa3c832 in expand_smacro modules/preprocs/nasm/nasm-pp.c:4104
    #4 0x564e5fa35a41 in do_directive modules/preprocs/nasm/nasm-pp.c:3174
    #5 0x564e5fa430aa in pp_getline modules/preprocs/nasm/nasm-pp.c:5075
    #6 0x564e5fa20be0 in nasm_preproc_get_line modules/preprocs/nasm/nasm-preproc.c:195
    #7 0x564e5fa155c3 in nasm_parser_parse modules/parsers/nasm/nasm-parse.c:218
    #8 0x564e5fa140af in nasm_do_parse modules/parsers/nasm/nasm-parser.c:66
    #9 0x564e5fa14230 in nasm_parser_do_parse modules/parsers/nasm/nasm-parser.c:83
    #10 0x564e5f9ad901 in do_assemble frontends/yasm/yasm.c:519


    #11 0x564e5f9ae6bf in main frontends/yasm/yasm.c:749
    #12 0x7fd4a5d51c86 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21c86)

SUMMARY: AddressSanitizer: 49 byte(s) leaked in 14 allocation(s).
```
### 9.source code：
nasm-pp.c
```
else
{
if (txtlen == 0)
txtlen = strlen(text);
t->text = nasm_malloc(1 + txtlen); <-- this
strncpy(t->text, text, txtlen);
t->text[txtlen] = '\0';
}
```
