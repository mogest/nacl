#include <ruby.h>
#include <crypto_box.h>
#include <crypto_sign.h>
#include <crypto_secretbox.h>
#include <crypto_hash.h>
#include <crypto_hash_sha256.h>
#include <crypto_hash_sha512.h>

VALUE NaCl = Qnil, OpenError = Qnil;

#define CHECK_STRING_LENGTH(str, len) do { Check_Type(str, T_STRING); if (RSTRING_LEN(str) != len) rb_raise(rb_eArgError, #str " must be %d bytes long", len); } while (0)

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
    CHECK_STRING_LENGTH(nonce, crypto_box_NONCEBYTES);
    CHECK_STRING_LENGTH(pk, crypto_box_PUBLICKEYBYTES);
    CHECK_STRING_LENGTH(sk, crypto_box_SECRETKEYBYTES);

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
    CHECK_STRING_LENGTH(nonce, crypto_box_NONCEBYTES);
    CHECK_STRING_LENGTH(pk, crypto_box_PUBLICKEYBYTES);
    CHECK_STRING_LENGTH(sk, crypto_box_SECRETKEYBYTES);

    mlen = allocate_and_prepend_zeros(ciphertext, crypto_box_BOXZEROBYTES, &padded_ciphertext, &result);
    n = crypto_box_open(result, padded_ciphertext, mlen, RSTRING_PTR(nonce), RSTRING_PTR(pk), RSTRING_PTR(sk));

    if (n == 0) return_value = rb_str_new(result + crypto_box_ZEROBYTES, mlen - crypto_box_ZEROBYTES);
    memset(result, 0, mlen);
    free(padded_ciphertext);
    free(result);
    if (n != 0) rb_raise(OpenError, "crypto_box_open failed");
    return return_value;
}

/**********************************************************************************/

VALUE method_crypto_sign_keypair(VALUE self) {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    VALUE keys[2];

    crypto_sign_keypair(pk, sk);
    keys[0] = rb_str_new(pk, crypto_sign_PUBLICKEYBYTES);
    keys[1] = rb_str_new(sk, crypto_sign_SECRETKEYBYTES);
    return rb_ary_new4(2, keys);
}

VALUE method_crypto_sign(VALUE self, VALUE message, VALUE sk) {
    char *result;
    VALUE return_value;
    unsigned long long smlen;

    Check_Type(message, T_STRING);
    CHECK_STRING_LENGTH(sk, crypto_sign_SECRETKEYBYTES);

    result = (char *)malloc(RSTRING_LEN(message) + crypto_sign_BYTES);
    if (result == NULL) rb_raise(rb_eNoMemError, "out of memory");

    crypto_sign(result, &smlen, RSTRING_PTR(message), RSTRING_LEN(message), RSTRING_PTR(sk));

    return_value = rb_str_new(result, smlen);
    free(result);
    return return_value;
}

VALUE method_crypto_sign_open(VALUE self, VALUE signed_message, VALUE pk) {
    char *result;
    VALUE return_value;
    unsigned long long mlen;
    int n;

    Check_Type(signed_message, T_STRING);
    if (RSTRING_LEN(signed_message) == 0) rb_raise(OpenError, "crypto_sign_open failed");
    CHECK_STRING_LENGTH(pk, crypto_sign_PUBLICKEYBYTES);

    result = (char *)malloc(RSTRING_LEN(signed_message));
    if (result == NULL) rb_raise(rb_eNoMemError, "out of memory");

    n = crypto_sign_open(result, &mlen, RSTRING_PTR(signed_message), RSTRING_LEN(signed_message), RSTRING_PTR(pk));

    if (n == 0) return_value = rb_str_new(result, mlen);
    free(result);
    if (n != 0) rb_raise(OpenError, "crypto_sign_open failed");
    return return_value;
}

/**********************************************************************************/

VALUE method_crypto_secretbox(VALUE self, VALUE message, VALUE nonce, VALUE key) {
    char *padded_message, *result;
    VALUE return_value;
    unsigned long long mlen;
    int n;

    Check_Type(message, T_STRING);
    CHECK_STRING_LENGTH(nonce, crypto_secretbox_NONCEBYTES);
    CHECK_STRING_LENGTH(key, crypto_secretbox_KEYBYTES);

    mlen = allocate_and_prepend_zeros(message, crypto_secretbox_ZEROBYTES, &padded_message, &result);
    n = crypto_secretbox(result, padded_message, mlen, RSTRING_PTR(nonce), RSTRING_PTR(key));

    if (n == 0) return_value = rb_str_new(result + crypto_secretbox_BOXZEROBYTES, mlen - crypto_secretbox_BOXZEROBYTES);
    memset(padded_message, 0, mlen);
    free(result);
    free(padded_message);
    if (n != 0) rb_raise(rb_eRuntimeError, "crypto_secretbox failed");
    return return_value;
}

VALUE method_crypto_secretbox_open(VALUE self, VALUE ciphertext, VALUE nonce, VALUE key) {
    char *p, *padded_ciphertext, *result;
    VALUE return_value;
    unsigned long long mlen;
    int n;

    Check_Type(ciphertext, T_STRING);
    if (RSTRING_LEN(ciphertext) < crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES) rb_raise(rb_eArgError, "ciphertext must be at least %d bytes long", crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES);
    CHECK_STRING_LENGTH(nonce, crypto_secretbox_NONCEBYTES);
    CHECK_STRING_LENGTH(key, crypto_secretbox_KEYBYTES);

    mlen = allocate_and_prepend_zeros(ciphertext, crypto_secretbox_BOXZEROBYTES, &padded_ciphertext, &result);
    n = crypto_secretbox_open(result, padded_ciphertext, mlen, RSTRING_PTR(nonce), RSTRING_PTR(key));

    if (n == 0) return_value = rb_str_new(result + crypto_secretbox_ZEROBYTES, mlen - crypto_secretbox_ZEROBYTES);
    memset(result, 0, mlen);
    free(padded_ciphertext);
    free(result);
    if (n != 0) rb_raise(OpenError, "crypto_secretbox_open failed");
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
    rb_define_const(NaCl, "BOX_NONCE_LENGTH", INT2FIX(crypto_box_NONCEBYTES));

    rb_define_module_function(NaCl, "crypto_sign_keypair", method_crypto_sign_keypair, 0);
    rb_define_module_function(NaCl, "crypto_sign", method_crypto_sign, 2);
    rb_define_module_function(NaCl, "crypto_sign_open", method_crypto_sign_open, 2);

    rb_define_module_function(NaCl, "crypto_secretbox", method_crypto_secretbox, 3);
    rb_define_module_function(NaCl, "crypto_secretbox_open", method_crypto_secretbox_open, 3);
    rb_define_const(NaCl, "SECRETBOX_NONCE_LENGTH", INT2FIX(crypto_secretbox_NONCEBYTES));
    rb_define_const(NaCl, "SECRETBOX_KEY_LENGTH", INT2FIX(crypto_secretbox_KEYBYTES));

    rb_define_module_function(NaCl, "crypto_hash", method_crypto_hash, 1);
    rb_define_module_function(NaCl, "crypto_hash_sha256", method_crypto_hash_sha256, 1);
    rb_define_module_function(NaCl, "crypto_hash_sha512", method_crypto_hash_sha512, 1);

    OpenError = rb_define_class_under(NaCl, "OpenError", rb_eStandardError);
}
