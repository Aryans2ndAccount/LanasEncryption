#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 10000

void tea_encrypt(uint32_t* v, const uint32_t* k) {
  uint32_t v0 = v[0], v1 = v[1], sum = 0;
  uint32_t delta = 0x9e3779b9;
  for (unsigned int i = 0; i < 32; i++) {
    sum += delta;
    v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
    v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
  }
  v[0] = v0;
  v[1] = v1;
}

void tea_decrypt(uint32_t* v, const uint32_t* k) {
  uint32_t v0 = v[0], v1 = v[1];
  uint32_t delta = 0x9e3779b9;
  uint32_t sum = 0xC6EF3720; // 32*delta
  for (unsigned int i = 0; i < 32; i++) {
    v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
    sum -= delta;
  }
  v[0] = v0;
  v[1] = v1;
}

int main (int argc, char* argv[]) {
  
  uint32_t key[4] = { 0x0519, 0x1905, 0x6942, 0x4269 };

  if (!strcmp(argv[1], "encrypt")) {
    char *buffer = (char *)malloc(BUFFER_SIZE);
    buffer[0] = '\0';

    //reading inputs
    size_t orig_length = 0;
    for (int i = 2; i < argc; i++) {
      strcat(buffer, argv[i]);
      strcat(buffer, " ");
      orig_length += strlen(argv[i]) + 1;
    }
    if (orig_length > 0 && buffer[orig_length - 1] == ' ') {
      buffer[orig_length - 1] = '\0';
      orig_length--;
    }

    //padding inputs in accordance with T.E.A. alg
    size_t pad = 8 - (orig_length % 8);
    if (pad == 0) pad = 8;
    size_t padded_length = orig_length + pad;
    for (size_t i = 0; i < pad; i++) {
      buffer[orig_length + i] = (char)pad;
    }

    buffer[padded_length] = '\0';

    //actual encryption
    uint32_t *data = (uint32_t *)buffer;
    size_t num_words = padded_length / 4;

    printf("encrypting...\n");
    for (size_t i = 0; i < num_words; i += 2) {
      tea_encrypt(&data[i], key);
    }

    for (size_t i = 0; i < num_words; i++) {
      printf("%08x ", data[i]);
    }
    printf("\n");

    free(buffer);
  }
  //decrypt
  else if (!strcmp(argv[1], "decrypt")) {
    size_t num_words = argc - 2;
    
    uint32_t *data = (uint32_t *)malloc(num_words * sizeof(uint32_t));
    if (!data) {
      perror("malloc failed");
      return 1;
    }

    //convert each hex string into uint32_t
    for (size_t i = 0; i < num_words; i++) {
      sscanf(argv[i + 2], "%x", &data[i]);
    }

    printf("decrypting...\n");
    for (size_t i = 0; i < num_words; i += 2) {
      tea_decrypt(&data[i], key);
    }
    
    //actual decryption
    size_t total_bytes = num_words * 4;
    unsigned char pad = ((unsigned char*)data)[total_bytes - 1];
    if (pad > 0 && pad <= 8) {
      total_bytes -= pad;
    }

    printf("Result: %.*s\n", (int)total_bytes, (char *)data);

    free(data);
  }
  else {
    printf("Invalid argument. Use 'encrypt' or 'decrypt'.\n");
    return 1;
  }

  return 0;
}
