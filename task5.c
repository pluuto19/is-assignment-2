#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

int main ()
{
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *sig = BN_new();
  BIGNUM *ver = BN_new();

  BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
  BN_hex2bn(&e, "010001");
  BN_hex2bn(&sig, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

  BN_mod_exp(ver, sig, e, n, ctx);

  char *ver_hex = BN_bn2hex(ver);

  for (int i = 0; ver_hex[i] != '\0'; i++) {
        printf("%c", ver_hex[i]);
  }

  printf("\n");

  return 0;
}

