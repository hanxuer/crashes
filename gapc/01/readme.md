### The name of the affected product:
GPAC MP4Box

### The affect version
```
MP4Box - GPAC version 2.3-DEV-revrelease
(c) 2000-2023 Telecom Paris distributed under LGPL v2.1+ - https://gpac.io

Please cite our work in your research:
	GPAC Filters: https://doi.org/10.1145/3339825.3394929
	GPAC: https://doi.org/10.1145/1291233.1291452

GPAC Configuration: 
Features: GPAC_CONFIG_LINUX GPAC_64_BITS GPAC_HAS_IPV6 GPAC_HAS_SOCK_UN GPAC_MINIMAL_ODF GPAC_HAS_QJS GPAC_HAS_JPEG GPAC_HAS_PNG GPAC_HAS_LINUX_DVB  GPAC_DISABLE_3D 
```
### Description
GPAC v2.3 8684dfb was detected to contain a buffer overflow via the function gf_isom_new_generic_sample_description function in the isomedia/isom_write.c:4577

### Vulnerability Type
buffer overflow

### Test environment
```
$ uname -a
Linux ubuntu 5.4.0-152-generic #169~18.04.1-Ubuntu SMP Wed Jun 7 22:22:24 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

### Compiler with asan
vendor link：https://github.com/gpac/gpac
```
$ ./configure --enable-sanitizer 
$ make
```

### How to reproduce
./bin/gcc/MP4Box -dash 10000 ./poc    
poc link：https://github.com/hanxuer/crashes/raw/main/gapc/01/poc.zip

### Report
GDB backtrace:
*** buffer overflow detected ***: ../../gpac-asan/bin/gcc/MP4Box terminated
```
#0  __GI_raise (sig=sig@entry=0x6) at ../sysdeps/unix/sysv/linux/raise.c:51
#1  0x00007ffff20a27f1 in __GI_abort () at abort.c:79
#2  0x00007ffff20eb837 in __libc_message (action=action@entry=(do_abort | do_backtrace), fmt=fmt@entry=0x7ffff2218869 "*** %s ***: %s terminated\n") at ../sysdeps/posix/libc_fatal.c:181
#3  0x00007ffff2196b5f in __GI___fortify_fail_abort (need_backtrace=need_backtrace@entry=0x1, msg=msg@entry=0x7ffff22187e6 "buffer overflow detected") at fortify_fail.c:33
#4  0x00007ffff2196b81 in __GI___fortify_fail (msg=msg@entry=0x7ffff22187e6 "buffer overflow detected") at fortify_fail.c:44
#5  0x00007ffff2194870 in __GI___chk_fail () at chk_fail.c:28
#6  0x00007ffff2193b02 in __strcpy_chk (dest=dest@entry=0x612000001426 "", src=src@entry=0x7ffffffe2f94 " MPEG-4 AVC|H264 Multiview Video ", destlen=destlen@entry=0x21) at strcpy_chk.c:30
#7  0x00007ffff4682517 in strcpy (__src=0x7ffffffe2f94 " MPEG-4 AVC|H264 Multiview Video ", __dest=0x612000001426 "") at /usr/include/x86_64-linux-gnu/bits/string_fortified.h:90
#8  gf_isom_new_generic_sample_description (movie=<optimized out>, trackNumber=<optimized out>, URLname=URLname@entry=0x0, URNname=URNname@entry=0x0, udesc=udesc@entry=0x7ffffffe2f60, outDescriptionIndex=outDescriptionIndex@entry=0x617000011564) at isomedia/isom_write.c:4577
#9  0x00007ffff51556ad in mp4_mux_setup_pid (filter=<optimized out>, pid=0x613000001000, is_true_pid=<optimized out>) at filters/mux_isom.c:3218
#10 0x00007ffff4da6a44 in gf_filter_pid_configure (filter=filter@entry=0x619000014a80, pid=<optimized out>, ctype=ctype@entry=GF_PID_CONF_CONNECT) at filter_core/filter_pid.c:881
#11 0x00007ffff4dadedf in gf_filter_pid_connect_task (task=0x607000000f70) at filter_core/filter_pid.c:1241
#12 0x00007ffff4de4ea1 in gf_fs_thread_proc (sess_thread=sess_thread@entry=0x616000001c10) at filter_core/filter_session.c:2100
#13 0x00007ffff4de8e94 in gf_fs_run (fsess=0x616000001b80) at filter_core/filter_session.c:2400
#14 0x00007ffff47dfe76 in gf_dasher_process (dasher=<optimized out>) at media_tools/dash_segmenter.c:1255
#15 0x00005555555d7622 in do_dash () at mp4box.c:4832
#16 0x00005555555f5bb7 in mp4box_main (argc=<optimized out>, argv=<optimized out>) at mp4box.c:6256
#17 0x00007ffff2083c87 in __libc_start_main (main=0x5555555db180 <main>, argc=0x4, argv=0x7fffffffdae8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdad8) at ../csu/libc-start.c:310
#18 0x00005555555db23a in _start ()
```

### Vul in source code：
isom_write.c
```c
entry->Height = udesc->height;
		strcpy(entry->compressor_name, udesc->compressor_name);            // this
		entry->color_table_index = -1;
```
