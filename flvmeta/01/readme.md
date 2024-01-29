### 1.The name and version of the affected product:
```
flvmeta 1.2.2

Copyright (C) 2007-2019 Marc Noirot <marc.noirot AT gmail.com>
This is free software; see the source for copying conditions. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

### 2.Description
flvmeta v1.2.2 was detected to contain a heap-use-after-free via the function flvmeta/src/flv.c:375:21 in flv_close

### 3.environment
```
$ uname -a
Linux ubuntu 5.4.0-152-generic #169~18.04.1-Ubuntu SMP Wed Jun 7 22:22:24 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

### 4.compiler with asan
```
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-fsanitize=address"
make
```

### 5.how to reproduce
./flvmeta/build/src/flvmeta ./poc

### 6.Asan report
```
==129869==ERROR: AddressSanitizer: heap-use-after-free on address 0x604000000010 at pc 0x000000539f2c bp 0x7ffc37b92ee0 sp 0x7ffc37b92ed8
READ of size 8 at 0x604000000010 thread T0
    #0 0x539f2b in flv_close /flvmeta/flvmeta/src/flv.c:375:21
    #1 0x53bce3 in flv_parse /flvmeta/flvmeta/src/flv.c:525:17
    #2 0x52c487 in dump_metadata /flvmeta/flvmeta/src/dump.c:180:14
    #3 0x53c9cb in main /flvmeta/flvmeta/src/flvmeta.c:385:50
    #4 0x7faea13ddc86 in __libc_start_main /build/glibc-CVJwZb/glibc-2.27/csu/../csu/libc-start.c:310
    #5 0x41c7f9 in _start (/flvmeta/flvmeta/build/src/flvmeta+0x41c7f9)

0x604000000010 is located 0 bytes inside of 40-byte region [0x604000000010,0x604000000038)
freed by thread T0 here:
    #0 0x4dc4e0 in __interceptor_free.localalias.0 (/flvmeta/flvmeta-cov/build/src/flvmeta+0x4dc4e0)
    #1 0x539f79 in flv_close /flvmeta/flvmeta/src/flv.c:378:9
    #2 0x539e83 in flv_read_video_tag /flvmeta/flvmeta/src/flv.c:250:13
    #3 0x53bc93 in flv_parse /flvmeta/flvmeta/src/flv.c:523:22
    #4 0x52c487 in dump_metadata /flvmeta/flvmeta/src/dump.c:180:14
    #5 0x53c9cb in main /flvmeta/flvmeta/src/flvmeta.c:385:50
    #6 0x7faea13ddc86 in __libc_start_main /build/glibc-CVJwZb/glibc-2.27/csu/../csu/libc-start.c:310

previously allocated by thread T0 here:
    #0 0x4dc6b0 in malloc (/flvmeta/flvmeta/build/src/flvmeta+0x4dc6b0)
    #1 0x53771a in flv_open /flvmeta/flvmeta/src/flv.c:52:42
    #2 0x53b5d9 in flv_parse /flvmeta/flvmeta/src/flv.c:480:22
    #3 0x52c487 in dump_metadata /flvmeta/flvmeta/src/dump.c:180:14
    #4 0x53c9cb in main /flvmeta/flvmeta/src/flvmeta.c:385:50
    #5 0x7faea13ddc86 in __libc_start_main /build/glibc-CVJwZb/glibc-2.27/csu/../csu/libc-start.c:310

SUMMARY: AddressSanitizer: heap-use-after-free /flvmeta/flvmeta-cov/src/flv.c:375:21 in flv_close
Shadow bytes around the buggy address:
  0x0c087fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c087fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c087fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c087fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c087fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c087fff8000: fa fa[fd]fd fd fd fd fa fa fa fa fa fa fa fa fa
  0x0c087fff8010: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==129869==ABORTING
```

gdb backtrace
```
gef➤  bt
#0  __GI_raise (sig=sig@entry=0x6) at ../sysdeps/unix/sysv/linux/raise.c:51
#1  0x00007ffff76847f1 in __GI_abort () at abort.c:79
#2  0x00007ffff76cd837 in __libc_message (action=action@entry=do_abort, fmt=fmt@entry=0x7ffff77faa7b "%s\n") at ../sysdeps/posix/libc_fatal.c:181
#3  0x00007ffff76d48ba in malloc_printerr (str=str@entry=0x7ffff77fc6e8 "free(): double free detected in tcache 2") at malloc.c:5342
#4  0x00007ffff76dc0ed in _int_free (have_lock=0x0, p=0x693250, av=0x7ffff7a2fc40 <main_arena>) at malloc.c:4195
#5  __GI___libc_free (mem=0x693260) at malloc.c:3134
#6  0x00000000004223d3 in flv_close (stream=0x693260) at /home/hanxuerr/myfuzz/target_program/flvmeta/flvmeta/src/flv.c:378
#7  0x000000000042394c in flv_parse (file=<optimized out>, parser=<optimized out>) at /flvmeta/flvmeta/src/flv.c:525
#8  0x000000000041a41d in dump_metadata (options=0x652530 <main.options>) at /flvmeta/flvmeta/src/dump.c:180
#9  0x0000000000424937 in main (argc=<optimized out>, argv=<optimized out>) at /flvmeta/flvmeta/src/flvmeta.c:385
```

### source code
```c
void flv_close(flv_stream * stream) {
    if (stream != NULL) {
        if (stream->flvin != NULL) {
            fclose(stream->flvin);
        }
        free(stream); // flv.c:378
    }
}


else if (tag.type == FLV_TAG_TYPE_VIDEO) {
            retval = flv_read_video_tag(parser->stream, &vt);
            if (retval == FLV_ERROR_EOF) {
                flv_close(parser->stream);  //flv.c:525
                return retval;
            }
```
