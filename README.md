# rgbctf-pwn

`Solution script for RGBCTF soda-pop-bop pwn challenge`



# HOUSE OF FORCE

### Finding the bug was actually simple
```py
00000ccb  *party = malloc(zx.q(*party_size) << 5)
00000ce5  if (*party == 0)
00000ce5      puts(data_109f)  {"You can't have a party of 0!"}
00000cef      exit(1)
00000cef      noreturn
00000cfa  if (*party_size u<= 1)
00000d9b      puts(data_10da)  {"All alone...? I'm so sorry :("}
00000da7      *(*party + 0x18) = -1 <---------------- It puts the -1 to the top chunk if the Party size we give is "0".
00000db6      puts(data_10f8)  {"What's your name?"}
00000dc7      printf(data_f5f)
00000dd3      uint64_t rdx_7 = *party
00000de8      fgets(rdx_7, 0x18, stdin, rdx_7)
00000d03  else
00000d03      int32_t var_c_1 = 0
00000d81      while (true)
00000d81          uint64_t rdx_6 = zx.q(var_c_1)
00000d8c          if (rdx_6:0.d u<= *party_size)
00000d8c              break
00000d1d          printf(data_10bc, zx.q(var_c_1), rdx_6)  {"What's the name of member %d?"}
00000d2e          printf(data_f5f)
00000d47          *(*party + (sx.q(var_c_1) << 5) + 0x18) = -1
00000d67          int64_t rdx_4 = *party + (sx.q(var_c_1) << 5)
00000d78          fgets(rdx_4, 0x18, stdin, rdx_4)
00000d7d          var_c_1 = var_c_1 + 1
```
There was this else condition IT never gets executed, The author said it was'nt intended. IT's just a decoy (;


```py
00000df2  while (true)
00000df2      print_menu()
00000e06      char var_d_1 = _IO_getc(stdin):0.b
00000e13      _IO_getc(stdin)
00000e18      uint64_t rax_18 = zx.q(sx.d(var_d_1))
00000e1c      if (rax_18:0.d == 0x32)
00000e4a          get_drink()
00000e21      else
00000e21          if (rax_18:0.d s> 0x32)
00000e2d              if (rax_18:0.d == 0x33)
00000e56                  sing_song()
00000e5b                  continue
00000e62              else if (rax_18:0.d == 0x34)
00000e62                  exit(0)
00000e62                  noreturn
00000e26          else if (rax_18:0.d == 0x31)
00000e3e              choose_song()
00000e43              continue
00000e6e          puts(data_110a)  {"????"}
```


### choose_song function just asks for no.of bytes to allocate and reads the data into it.
```py
000009da  puts(data_f44)  {"How long is the song name?"}
000009eb  printf(data_f5f)
00000a03  int64_t var_18
00000a03  __isoc99_scanf(data_f62, &var_18)  {"%llu"}
00000a12  _IO_getc(stdin)
00000a23  *selected_song = malloc(var_18)
00000a31  puts(data_f67)  {"What is the song title?"}
00000a42  printf(data_f5f)
00000a52  uint64_t rcx = zx.q(var_18:0.d)
00000a60  fgets(*selected_song, zx.q(rcx:0.d), stdin, rcx)
```

### singsong() function just prints the pointer which is returened by malloc ( We leak addresses using this function. )
```py
  return printf(data_f2e, *selected_song)  {"You sang %p so well!\n"}```
  


