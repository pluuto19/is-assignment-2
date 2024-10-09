#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

int main ()
{
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *n = BN_new();
  BIGNUM *d = BN_new();
  BIGNUM *message = BN_new();
  BIGNUM *sig = BN_new();

  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
  BN_hex2bn(&message, "49206F776520796F752024323030302E");

  BN_mod_exp(sig, message, d, n, ctx);

  char *sig_hex = BN_bn2hex(sig);

  for (int i = 0; sig_hex[i] != '\0'; i++) {
        printf("%c", sig_hex[i]);
  }

  printf("\n");

  return 0;
}

