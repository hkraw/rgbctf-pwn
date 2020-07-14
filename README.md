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
```


