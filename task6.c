#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

BIGNUM* hex_to_bn(const char* hex_str) {
    BIGNUM* bn = BN_new();
    BN_hex2bn(&bn, hex_str);
    return bn;
}

void hex_to_bytes(const char* hex_str, unsigned char* byte_array, size_t* byte_array_len) {
    size_t len = strlen(hex_str);
    *byte_array_len = len / 2;
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex_str + i, "%2hhx", &byte_array[i / 2]);
    }
}

void verify_signature(const char* modulus_hex, const char* exponent_hex, const char* signature_hex, const char* hash_hex) {
    BIGNUM* bn_modulus = hex_to_bn(modulus_hex);
    BIGNUM* bn_exponent = hex_to_bn(exponent_hex);
    BIGNUM* bn_signature = hex_to_bn(signature_hex);

    unsigned char expected_hash[32];
    size_t hash_len;
    hex_to_bytes(hash_hex, expected_hash, &hash_len);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bn_decrypted_hash = BN_new();
    BN_mod_exp(bn_decrypted_hash, bn_signature, bn_exponent, bn_modulus, ctx);

    unsigned char decrypted_hash[256];
    int decrypted_len = BN_bn2bin(bn_decrypted_hash, decrypted_hash);

    if (decrypted_len >= 32 && memcmp(decrypted_hash + (decrypted_len - 32), expected_hash, 32) == 0) {
        printf("The signature is valid.\n");
    } else {
        printf("The signature is not valid.\n");
    }

    BN_free(bn_modulus);
    BN_free(bn_exponent);
    BN_free(bn_signature);
    BN_free(bn_decrypted_hash);
    BN_CTX_free(ctx);
}

int main() {
    const char* modulus_hex = "CCF710624FA6BB636FED905256C56D277B7A12568AF1F4F9D6E7E18FBD95ABF260411570DB1200FA270AB557385B7DB2519371950E6A41945B351BFA7BFABBC5BE2430FE56EFC4F37D97E314F5144DCBA710F216EAAB22F031221161699026BA78D9971FE37D66AB75449573C8ACFFEF5D0A8A5943E1ACB23A0FF348FCD76B37C163DCDE46D6DB45FE7D23FD90E851071E51A35FED4946547F2C88C5F4139C97153C03E8A139DC690C32C1AF16574C9447427CA2C89C7DE6D44D54AF4299A8C104C2779CD648E4CE11E02A8099F04370CF3F766BD14C49AB245EC20D82FD46A8AB6C93CC6252427592F89AFA5E5EB2B061E51F1FB97F0998E83DFA837F4769A1";
    const char* exponent_hex = "10001";
    const char* signature_hex = "04e16e023e0de32346f4e3963505933522020b845de27386d4744ffc1b27af3ecaadc3ce46d6fa0fe271f90d1a9a13b7d50848bd5058b35e20638629ca3ecccc7826e1598f5dca8bbc49316f61bd42ff6162e1223524269b57ebe5000dff40336c46c233770898b27af643f96d48dfbffefa281e7b8acf2d61ff6c8798a42c629abb108cff34487066b76d72c369f9394b683956bda1b36df477f3465b5c19ac4fb3746b8cc5f189cc93fe0c016f8817dc427160e3ed7330429ca92f3ba2788ec86fbad1130cd0c75e8c10fb012e379bdbacf7a1acba7ff892e7cb4144c815f9f3c4bbad515fbedec7ac86079f40ecb90bf6b28bccb5553366ba33c2c4f0a2e9";
    const char* hash_hex = "b2825cb7d71ec7093e7ff7026c562a29122de3b4900ed13dad63d1be73706e0d";

    verify_signature(modulus_hex, exponent_hex, signature_hex, hash_hex);

    return 0;
}

