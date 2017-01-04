#include <iostream>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "include/SKF.h"
#include <time.h>

#include <windows.h>
#include "test.cpp"
#include "include/openssl_helper.h"

using namespace std;


int main(int argc, char *argv[])
{
    unsigned int r1;
    int i;
    unsigned int r;
    unsigned int len;
    int ret;
    HANDLE hKey;
    HANDLE hDev;
    int enc_len;
    int dec_len;
    int data_size;
    unsigned char *source_data = NULL;
    unsigned char *enc_data = NULL;
    unsigned char *dec_data = NULL;
    BLOCKCIPHERPARAM bp;
//	char *pBuf;
    struct timeval start_time, finish_time;
    double enc_total_val = 0;
    double dec_total_val = 0;

    /*******************************************/

    char  pchTemp[MAX_PATH],path[MAX_PATH],Dllpath[MAX_PATH];

    GetCurrentDirectoryA(MAX_PATH,path);
    printf("get current path :[%s]\n",path);
    strcpy(Dllpath,path);
    strcat(Dllpath,"\\SKF_sd.dll");
    printf("Load DLL [%s]\n",Dllpath);


    if(load_skf_dll(Dllpath)) {
        printf("load sfk DLL fail .\n");
        return -1;
    }


    connect_device();
    ret = get_deviceinfo(devHandle);
    ret = get_devicestate();
    //ret = set_label("hangzhouchuangxie");
    //ret = get_deviceinfo(devHandle);

    ret = open_application();
    ret = get_pininfo();
    ret = verify_pin("111111");

    ret = enum_container();
    //ret = open_container("KingTrustVPN");

    //ret = create_container("SM2Container");
    ret = open_container("SM2Container");
    ret = enum_container();
    if(1) {
        //ret = import_certificate("sm2_client.der",CERT_TYPE_ENC);
        //ret = import_certificate("sm2_client.der",CERT_TYPE_SIGN);
        //ret = import_certificate("rsa_client.der");

        ret = import_sm2_cert();

        ret = get_containerType();
        //ret = export_certificate(CERT_TYPE_SIGN);
        ret = export_certificate(CERT_TYPE_ENC);
    }

    if(0) {
        ret = create_file("sm2.cert",1024);
        ret = enum_file();
        ret = get_file_info("sm2.cert");
        char *txt = "hello skf api,fuck you !";
        ret = write_file("sm2.cert",txt,0,strlen(txt));

        char data[1024] = {0};
        ret = read_file("sm2.cert",0,128,data);
        printf("Read data [%s]\n",data);

        ret = del_file("sm2.cert");
        ret = enum_file();

    }
    if(0) {
            ret = create_and_writefile("client.crt","testcert.crt");
            ret = read_and_savefile("testcert.crt","out.crt");
    }


    //ret =  change_pin("111111","111111");

    /*********************************************************/

    EC_KEY *eckey = NULL;
    eckey = load_key("sm2_client.key",1);
    if(eckey == NULL) {
        printf("read ECC key ERROR.\n");
    }


    return 0;
}

















