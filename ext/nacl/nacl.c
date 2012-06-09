#include <ruby.h>
#include <crypto_box.h>
#include <crypto_hash.h>
#include <crypto_hash_sha256.h>
#include <crypto_hash_sha512.h>

VALUE NaCl = Qnil, BoxOpenError = Qnil;

unsigned long long allocate_and_prepend_zeros(VALUE source, unsigned long long padding_len, char **padded, char **result) {
    unsigned long long mlen = RSTRING_LEN(source) + padding_len;

    *padded = (char *)malloc(mlen);
    if (*padded == NULL) rb_raise(rb_eNoMemError, "out of memory");

    *result = (char *)malloc(mlen);
    if (*result == NULL)
    {
        free(*padded);
        rb_raise(rb_eNoMemError, "out of memory");
    }

    memset(*padded, 0, padding_len);
    memcpy(*padded + padding_len, RSTRING_PTR(source), RSTRING_LEN(source));
    return mlen;
}

/**********************************************************************************/

VALUE method_crypto_box_keypair(VALUE self) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    VALUE keys[2];

    crypto_box_keypair(pk, sk);
    keys[0] = rb_str_new(pk, crypto_box_PUBLICKEYBYTES);
    keys[1] = rb_str_new(sk, crypto_box_SECRETKEYBYTES);
    return rb_ary_new4(2, keys);
}

VALUE method_crypto_box(VALUE self, VALUE message, VALUE nonce, VALUE pk, VALUE sk) {
    char *padded_message, *result;
    VALUE return_value;
    unsigned long long mlen;
    int n;

    Check_Type(message, T_STRING);
    Check_Type(nonce, T_STRING);
    if (RSTRING_LEN(nonce) != crypto_box_NONCEBYTES) rb_raise(rb_eArgError, "nonce must be %d bytes long", crypto_box_NONCEBYTES);
    Check_Type(pk, T_STRING);
    if (RSTRING_LEN(pk) != crypto_box_PUBLICKEYBYTES) rb_raise(rb_eArgError, "public_key must be %d bytes long", crypto_box_PUBLICKEYBYTES);
    Check_Type(sk, T_STRING);
    if (RSTRING_LEN(pk) != crypto_box_SECRETKEYBYTES) rb_raise(rb_eArgError, "secret_key must be %d bytes long", crypto_box_SECRETKEYBYTES);

    mlen = allocate_and_prepend_zeros(message, crypto_box_ZEROBYTES, &padded_message, &result);
    n = crypto_box(result, padded_message, mlen, RSTRING_PTR(nonce), RSTRING_PTR(pk), RSTRING_PTR(sk));

    if (n == 0) return_value = rb_str_new(result + crypto_box_BOXZEROBYTES, mlen - crypto_box_BOXZEROBYTES);
    memset(padded_message, 0, mlen);
    free(result);
    free(padded_message);
    if (n != 0) rb_raise(rb_eRuntimeError, "crypto_box failed");
    return return_value;
}

VALUE method_crypto_box_open(VALUE self, VALUE ciphertext, VALUE nonce, VALUE pk, VALUE sk) {
    char *p, *padded_ciphertext, *result;
    VALUE return_value;
    unsigned long long mlen;
    int n;

    Check_Type(ciphertext, T_STRING);
    if (RSTRING_LEN(ciphertext) < crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES) rb_raise(rb_eArgError, "ciphertext must be at least %d bytes long", crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES);
    Check_Type(nonce, T_STRING);
    if (RSTRING_LEN(nonce) != crypto_box_NONCEBYTES) rb_raise(rb_eArgError, "nonce must be %d bytes long", crypto_box_NONCEBYTES);
    Check_Type(pk, T_STRING);
    if (RSTRING_LEN(pk) != crypto_box_PUBLICKEYBYTES) rb_raise(rb_eArgError, "public_key must be %d bytes long", crypto_box_PUBLICKEYBYTES);
    Check_Type(sk, T_STRING);
    if (RSTRING_LEN(pk) != crypto_box_SECRETKEYBYTES) rb_raise(rb_eArgError, "secret_key must be %d bytes long", crypto_box_SECRETKEYBYTES);

    mlen = allocate_and_prepend_zeros(ciphertext, crypto_box_BOXZEROBYTES, &padded_ciphertext, &result);
    n = crypto_box_open(result, padded_ciphertext, mlen, RSTRING_PTR(nonce), RSTRING_PTR(pk), RSTRING_PTR(sk));

    if (n == 0) return_value = rb_str_new(result + crypto_box_ZEROBYTES, mlen - crypto_box_ZEROBYTES);
    memset(result, 0, mlen);
    free(result);
    if (n != 0) rb_raise(BoxOpenError, "crypto_box_open failed");
    return return_value;
}


/**********************************************************************************/

VALUE method_crypto_hash(VALUE self, VALUE data) {
    unsigned char h[crypto_hash_BYTES];
    Check_Type(data, T_STRING);
    crypto_hash(h, RSTRING_PTR(data), RSTRING_LEN(data));
    return rb_str_new(h, crypto_hash_BYTES);
}

VALUE method_crypto_hash_sha256(VALUE self, VALUE data) {
    unsigned char h[crypto_hash_sha256_BYTES];
    Check_Type(data, T_STRING);
    crypto_hash_sha256(h, RSTRING_PTR(data), RSTRING_LEN(data));
    return rb_str_new(h, crypto_hash_sha256_BYTES);
}

VALUE method_crypto_hash_sha512(VALUE self, VALUE data) {
    unsigned char h[crypto_hash_sha512_BYTES];
    Check_Type(data, T_STRING);
    crypto_hash_sha512(h, RSTRING_PTR(data), RSTRING_LEN(data));
    return rb_str_new(h, crypto_hash_sha512_BYTES);
}

void Init_nacl() {
    NaCl = rb_define_module("NaCl");

    rb_define_module_function(NaCl, "crypto_box_keypair", method_crypto_box_keypair, 0);
    rb_define_module_function(NaCl, "crypto_box", method_crypto_box, 4);
    rb_define_module_function(NaCl, "crypto_box_open", method_crypto_box_open, 4);

    rb_define_module_function(NaCl, "crypto_hash", method_crypto_hash, 1);
    rb_define_module_function(NaCl, "crypto_hash_sha256", method_crypto_hash_sha256, 1);
    rb_define_module_function(NaCl, "crypto_hash_sha512", method_crypto_hash_sha512, 1);

    BoxOpenError = rb_define_class("NaCl::BoxOpenError", rb_eStandardError);
}
