#ifndef OPENSSL_HELPER_H
#define OPENSSL_HELPER_H

#include <string.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>



EC_KEY *load_key(char *keyfile,int format);


#endif // OPENSSL_HELPER_H
