#include "include/openssl_helper.h"
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/ec.h>


EC_KEY *load_key(char *keyfile, int format)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    EC_KEY *eckey = NULL;
    BIO *in = NULL;

    in = BIO_new(BIO_s_file());
    if(in == NULL){
        printf("error on new bio file.\n")    ;
        return NULL;
    }
    if(BIO_read_filename(in,keyfile) <=0 ) {
        printf("Set Bio File Error .\n");
        return NULL;
    }




    printf("goto read ec key!\n");

    eckey = PEM_read_bio_ECPrivateKey(in,NULL,NULL,NULL);


    if(eckey == NULL) {
        printf("read ec key error.\n");
    }

    const EC_POINT *point;
    point = EC_KEY_get0_public_key(eckey);





    if(in)
        BIO_free(in);

}
