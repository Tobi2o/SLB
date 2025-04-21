
# Stack

buffer offset = $ebp - 0xd0
canary 		  = $ebp - 0x8


# format function

```c
void format(char *param_1)

{
  long in_FS_OFFSET;
  int offset;
  int nbChars;
  int local_fc;
  int i;
  int j;
  byte *ptr_encrypted_string;
  byte *ptr_string;
  size_t len_param;
  byte buffer [200];
  long canary;
  byte currentChar;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  local_fc = 0;
  len_param = strlen(param_1);
  printf("[Q] Enter a string with a secret info to protect:");
  setbuf(stdin,(char *)0x0);
  fgets((char *)buffer,1000,stdin);
  printf("[Q] At which position does your secret starts in the string:");
  FUN_00401160(&DAT_00402095,&offset);
  ptr_encrypted_string = buffer + offset;
  printf("[Q] How many characters do you want to encrypt:");
  FUN_00401160(&DAT_00402095,&nbChars);
  ptr_string = ptr_encrypted_string;
  printf("\n[I] Initial string = ");
  for (i = offset; i < nbChars + offset; i = i + 1) {
    currentChar = *ptr_string;
    ptr_string = ptr_string + 1;
    printf("%02hhx",(ulong)(uint)(int)(char)currentChar);
  }
  printf("\n[I] Encrypted string = ");
  for (j = offset; j < nbChars + offset; j = j + 1) {
    currentChar = *ptr_encrypted_string;
    ptr_encrypted_string = ptr_encrypted_string + 1;
    printf("%02hhx",(ulong)(uint)(int)(char)(param_1[local_fc] ^ currentChar));
    local_fc = (int)((ulong)(long)(local_fc + 1) % len_param);
  }
  putchar(10);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Since we can choose our offset + length to read, we can directly read the canary with the application.
We can set offset to 200, then read length to like 8 to have the full canary.

Now we can generate our own payload to smash the EIP value with the address to execute the win function.
200/8 bytes = 25. Donc on peut remplir le buffer avec 26*canary, ensuite le reste avec l'addr. de la fonction win.
