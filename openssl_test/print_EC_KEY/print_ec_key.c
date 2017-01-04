/*************************************************************************
  > File Name: print_ec_key.c
  > Author: ma6174
  > Mail: ma6174@163.com 
  > Created Time: 2017年01月03日 星期二 11时34分57秒
 ************************************************************************/

#include<stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/bn.h>


uint8_t priv[32];
uint8_t *pub;
uint8_t pub_x[32];
uint8_t pub_y[32];

const BIGNUM *priv_bn;
const EC_POINT *pub_point;
const EC_GROUP *ec_group;
BIGNUM *X;
BIGNUM *Y;

point_conversion_form_t conv_forms[] = {
	POINT_CONVERSION_UNCOMPRESSED,
	POINT_CONVERSION_COMPRESSED
};


static void print_hex(char *data,int len,char *prefix)
{
	int i = 0;
	if(prefix){
		printf("---%s----\n",prefix);
	}
	for(i = 0;i < len;i++) {
		if((i+1)%17 == 0)
			printf("\n");
		printf("%02x ",data[i]);
	}
	printf("\n---------\n",prefix);
}

EC_KEY *load_key(char *keyfile, int format)
{
	SSL_library_init();
	SSL_load_error_strings();

	EC_KEY *eckey = NULL;
	BIO *in = NULL;
	BIO *out = NULL;


	in = BIO_new(BIO_s_file());
	out = BIO_new(BIO_s_file());

	if(in == NULL){
		printf("error on new bio file.\n")    ;
		return NULL;
	}
	if(BIO_read_filename(in,keyfile) <=0 ) {
		printf("Set Bio File Error .\n");
		return NULL;
	}

	BIO_set_fp(out,stdout,BIO_NOCLOSE);



	printf("goto read ec key!\n");

	eckey = PEM_read_bio_ECPrivateKey(in,NULL,NULL,NULL);


	if(eckey == NULL) {
		printf("read ec key error.\n");
	}

	EC_KEY_print(out,eckey,0);

	if(in)
		BIO_free(in);


	return eckey;
}

int main(int argc,char *argv[])
{
	EC_KEY *key = NULL;
	key = load_key(argv[1],0);

	if(key != NULL) {
		//get priv key
		priv_bn = EC_KEY_get0_private_key(key);
		BN_bn2bin(priv_bn,priv);
		print_hex(priv,32,"priv key");
	}

	if(key != NULL) {
		pub_point = EC_KEY_get0_public_key(key);
		ec_group = EC_KEY_get0_group(key);
		if(pub_point != NULL) {
			X = BN_new();
			Y = BN_new();

			if (EC_POINT_get_affine_coordinates_GFp(ec_group, pub_point, X, Y, NULL)) {
				/*
				BN_print_fp(stdout, X);
				putc('\n', stdout);
				BN_print_fp(stdout, Y);
				putc('\n', stdout);
				*/
				BN_bn2bin(X,pub_x);
				BN_bn2bin(Y,pub_y);
				print_hex(pub_x,32,"----pub X----\n");
				print_hex(pub_y,32,"----pub Y----\n");
			}
		
		}
	}
}
