#include <iostream>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "include/SKF.h"
#include "include/skf_err_string.h"

#include <time.h>

#define DFT_LIB_NAME    "SKF_sd.dll"
#define LOG   printf

char *devName;                          //设备名
HMODULE H_DLL;                          //skf dll
PSKF_FUNCLIST FunctionList;             //方法集合
DEVHANDLE* devHandle;                   //操作句柄
HCONTAINER hContainer;                  //容器
HAPPLICATION hApplication;              //应用句柄

int load_skf_dll(char *dllpath)
{
    u32 r1;
    P_SKF_GetFuncList GetFunction = NULL;


     H_DLL = LoadLibraryA(dllpath);
    if(H_DLL == NULL)
    {
        r1 = GetLastError();
        printf("Load Error %d\n",r1);
        return r1;

    }else {
        printf("Load DLL Success.\n");

        GetFunction = (P_SKF_GetFuncList)GetProcAddress(H_DLL,"SKF_GetFuncList");
        if (GetFunction == NULL)
        {
            r1 = GetLastError();
            return r1;
        }
        printf("GetFunction  OK\n");
        r1 = GetFunction(&FunctionList);
        if (r1) return r1;
    }
    return 0;
}


DEVHANDLE * connect_device()
{
    u32 ret;
    //unsigned int len;
    u32 len;

    devName = NULL;
    ret = FunctionList->SKF_EnumDev(1, devName, &len);
    if(ret)
    {
        printf("SKF_EnumDev 1 error 0x%x\n", ret);
        return NULL;
    }
    printf("Get Dev size : %d\n",len);

    devName = (char *)malloc((size_t)len);
    if(devName == NULL)
    {
        printf("malloc error \n");
        return NULL;
    }

    ret = FunctionList->SKF_EnumDev(1, devName, &len);
    if(ret)
    {
        if(devName)
            free(devName);
        printf("SKF_EnumDev error 0x%x\n", ret);
        return NULL;
    }
    devHandle = (DEVHANDLE*)malloc(sizeof(DEVHANDLE));
    LOG("Open Devcie:%s\n",devName);
    ret = FunctionList->SKF_ConnectDev(devName, devHandle);
    if(ret)
    {
        if(devName)
            free(devName);
        if(devHandle)
            free(devHandle);
        devName = NULL;
        devHandle = NULL;
        printf("SKF_ConnectDev error 0x%x\n", ret);
        return NULL;
    }

    return devHandle;

}

int get_deviceinfo(DEVHANDLE *phDev)
{
    u32 ret = 0;
    DEVINFO *devInfo = new DEVINFO();

    ret = FunctionList->SKF_GetDevInfo(*phDev,devInfo);
    if(ret)
    {
        printf("SKF_GetDeviceInfo error 0x%x\n",ret);
        return -1;
    }
    printf("===========Get Device Info :==========\n");
    printf("Version      : %x.%x\n",devInfo->Version.major,devInfo->Version.minor);
    printf("Manufacrurer : %s\n",devInfo->Manufacturer);
    printf("Issuer       : %s\n",devInfo->Issuer);
    printf("Label        : %s\n",devInfo->Label);
    printf("SerialNumber : %s\n",devInfo->SerialNumber);
    printf("MaxBufferSize: %d\n",devInfo->MaxBufferSize);
    printf("TotalSpace   : %d\n",devInfo->TotalSpace);
    printf("=======================================\n");
    delete(devInfo);
}


int get_devicestate()
{
    u32 pulState;
    u32 ret;
    
    ret= FunctionList->SKF_GetDevState(devName,&pulState);
    if(ret)
    {
        printf("SKF_GetDeviceState error 0x%x\n",ret);
        return -1;
    }
    printf("The devicie stat[0x%x]\n",pulState);
    if(ret != DEV_PRESENT_STATE)
    {
        return -1;
    }

    return 0;
}

int set_label(char *label)
{
    u32 ret;

    ret=FunctionList->SKF_SetLabel(*devHandle,label);
    if(ret)
    {
        printf("SKF_SetLabel error 0x%x\n",ret);
        return -1;
    }

}



/*---- PIN ----*/
int change_pin(char *oldpin,char *newpin)
{
    u32 ret;
    u32 retryCount = 0;

    retryCount = 8;
    ret = FunctionList->SKF_ChangePIN(hApplication,USER_TYPE,oldpin,newpin,&retryCount);
    if(ret) {
        printf("SKF_ChangePin  error 0x%x  [%d]\n",ret,retryCount);
        return -1;
    }

    return 0;
}

int get_pininfo()
{
    u32 pulMaxRetryCount;
    u32 pulRemainRetryCount;
    BOOL pbDefaultPin;
    u32 ret;

    ret = FunctionList->SKF_GetPINInfo(hApplication,USER_TYPE,&pulMaxRetryCount,&pulRemainRetryCount,&pbDefaultPin);
    if(ret) {
        printf("SKF_getPinInfo  error 0x%x \n",ret);
        return -1;
    }
    printf("====Get Pin Info====\n");
    printf("MaxRetry [%d]\n",pulMaxRetryCount);
    printf("RemainRetry [%d]\n",pulRemainRetryCount);
    printf("Is Default PIN ? [%s]\n",pbDefaultPin?"YES":"NO");
    printf("=====================\n");

    return 0;
}


int verify_pin(char *userpin)
{
    u32 ret;
    u32 pulRemainRetryCount;

    //result = skf_verifyPIN(hApplication,USER_TYPE,"22222222",pulRemainRetryCount);
    ret = FunctionList->SKF_VerifyPIN(hApplication,USER_TYPE,userpin,&pulRemainRetryCount);
    if(ret) {
        printf("SKF_VerifyPin  error 0x%x [%d]\n",ret,pulRemainRetryCount);
        return -1;
    }
    printf("-----------> Verify PIN OK !!!\n");
    return 0;
}



/*---- Appliction ----*/
int open_application()
{
      u32 ret;
    u32 pulSize = 0;
    char *szAppName;


    ret = FunctionList->SKF_EnumApplication(*devHandle,NULL,&pulSize);
    if(ret) {
        printf("SKF_EnnumApplication len  error 0x%x\n",ret);
        return -1;
    }

    szAppName = (char *)malloc(pulSize);

    ret = FunctionList->SKF_EnumApplication(*devHandle,szAppName,&pulSize);
    if(ret) {
        printf("SKF_EnnumApplication len  error 0x%x\n",ret);
        return -1;
    }

    printf("EnumApplicatio[%d] : [%s] \n",pulSize,szAppName);
    ret = FunctionList->SKF_OpenApplication(*devHandle,szAppName,&hApplication);
    if(ret) {
        printf("SKF_OpenApplication len  error 0x%x\n",ret);
        return -1;
    }

    return 0;
}

int close_application()
{
    u32 ret;
    //result = skf_closeApplication(hApplication)
    ret = FunctionList->SKF_CloseApplication(hApplication);
    if(ret) {
        printf("SKF_CloseApplication  error 0x%x\n",ret);
        return -1;
    }
    return 0;
}

int create_application()
{
    u32 ret;
    u32 pulAdminRemainRetryCount;
    // handle,appName,AdminPIN,AdminRety,UerPin,UserRetry,FileRights,AppHandle
    ret = FunctionList->SKF_CreateApplication(*devHandle,"testApp","111111",8,"111111",8,SECURE_ANYONE_ACCOUNT,&hApplication);
    if(ret)
    {
        printf("SKF_CreateApplication error 0x%x\n",ret);
        return -1;
    }

}


/*------Container----------------*/

int enum_container()
{
    u32 ret;
    char* containerName;
    u32 containerSize;
    ret = FunctionList->SKF_EnumContainer(hApplication,NULL,&containerSize);
    if(ret){
        printf("SKF_EnumContainer len error 0x%x\n",ret);
        return -1;
    }


    containerName = (char *)malloc(containerSize);

    ret = FunctionList->SKF_EnumContainer(hApplication,containerName,&containerSize);
    if(ret){
        printf("SKF_EnumContainer  error 0x%x\n",ret);
        free(containerName);
        return -1;
    }
    int i = 0 ;
    printf("---EnumContainer---- \n");
    printf("---->[%s]\n",containerName);
    for(i = 1;i< containerSize;i++)
    {
        if(containerName[i] != '\0')
            continue;
        printf("---->[%s]\n",containerName+i+1);
    }
    printf("----------------------\n");

    free(containerName);
    return 0;
}


int open_container(char *name)
{
    u32 ret ;
    ret = FunctionList->SKF_OpenContainer(hApplication,name,&hContainer);
    if(ret){
        printf("SKF_OpenContainer  error 0x%x\n",ret);
        return -1;
    }

    printf("-------> Open Container %s OK !!!\n",name);
    return 0;
}

int get_containerType()
{
    u32 ret;
    u32 containerType;
    ret = FunctionList->SKF_GetContainerType(hContainer,&containerType);
    if(ret) {
        printf("SKF_GetContainerType  error 0x%x\n",ret);
        return -1;
    }
    if(containerType == CONTAINER_TYPE_NONE) {
        printf("Get ContainType [Empty].\n");
    }
    else {
        printf("Get ContainType [%s].\n",containerType==CONTAINER_TYPE_RSA?"RSA":"ECC");
    }


    return 0;

}

int create_container(char *name)
{
    u32 ret;
    ret = FunctionList->SKF_CreateContainer(hApplication,name,&hContainer);
    if(ret) {
        printf("SKF_CreateContainer  error 0x%x\n",ret);
        return -1;
    }
    return 0;

}




/*------------ Cert Opt ---------------*/
int export_certificate(int type)
{
    u32 ret;
    u8 * pbCertData;
    u32 certSize;
    //result = skf_exportCertificate(hContainer,TRUE,NULL,&certSize);
    //pbCertData = (BYTE*)malloc(sizeof(BYTE)*certSize);
    //result = skf_exportCertificate(hContainer,TRUE,NULL,&certSize);
    //签名密钥是内部生成的，加密密钥是外部导入的
    ret = FunctionList->SKF_ExportCertificate(hContainer,type,NULL,&certSize);
    if(ret){
        printf("SKF_Export [%s] Certificate size error 0x%x\n",type==CERT_TYPE_SIGN?"SIGN":"ENC",ret);
        return -1;
    }
    pbCertData = (u8 *)malloc(certSize);

    ret = FunctionList->SKF_ExportCertificate(hContainer,type,pbCertData,&certSize);
    if(ret) {
        printf("SKF_Export [%s] Certificate size error 0x%x\n",type==CERT_TYPE_SIGN?"SIGN":"ENC",ret);
        return -1;
    }

    printf("Get [%s] Cert Success,cert size = %d\n",type==CERT_TYPE_SIGN?"SIGN":"ENC",certSize);

    free(pbCertData);
    return 0;
}

int import_certificate(char *filename,int type)
{
    u32 ret;
    //char * containerName;
    //int  containerType;
    FILE *fp = NULL;
    u8 data[4096]={0};
    u32 data_len = 0;
    fp = fopen(filename,"rb");

    if(fp == NULL) {
        printf("Open file [%s] Fail.\n",filename);
        return -1;
    }

    data_len = fread(data,1,4096,fp);
    if(data_len <=0 ) {
        printf("Read file [%s] Fail.\n",filename);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    printf("Read Cert Len = %d\n",data_len);
    //result = skf_importCertificate(hContainer,FALSE,NULL,0);
    ret = FunctionList->SKF_ImportCertificate(hContainer,type,data,data_len);
    if(ret) {
        PRINT_KDF_ERROR(ret);
        printf("SKF_ImportCertificate  error 0x%x\n",ret);
        return -1;
    }

    return 0;
}


/*----file----*/
int create_file(char *filename,int size)
{
    u32 ret;
    u32 fileSize=size;
    //result = skf_createFile(hApplication,"test",fileSize,0x000000FF,0x000000FF);
    ret = FunctionList->SKF_CreateFile(hApplication,filename,fileSize,SECURE_ANYONE_ACCOUNT,SECURE_ANYONE_ACCOUNT);
    if(ret) {
        PRINT_KDF_ERROR(ret);
    }
    return ret;
}

int enum_file()
{
    u32 fileSize = 0;
    u32 ret;
    char* fileList;
    //SKF_EnumFiles skf_enumFiles = SKF_EnumFiles(GetProcAddress(hmodule,"SKF_EnumFiles"));
    ret = FunctionList->SKF_EnumFiles(hApplication,NULL,&fileSize);
    if(ret) {
        PRINT_KDF_ERROR(ret);
        return ret;
    }
    fileList = (char *)malloc(fileSize);
    ret = FunctionList->SKF_EnumFiles(hApplication,fileList,&fileSize);
    if(ret) {
        PRINT_KDF_ERROR(ret);
        return ret;
    }

    int i = 0 ;
    printf("---EnumFile---- \n");
    printf("---->[%s]\n",fileList);
    for(i = 1;i< fileSize;i++)
    {
        if(fileList[i] != '\0')
            continue;
        printf("---->[%s]\n",fileList+i+1);
    }
    printf("----------------------\n");
    free(fileList);
    return ret;
}



int get_file_info(char *filename)
{
    u32 ret;
    FILEATTRIBUTE fileAttribute;
    //result = skf_getFileInfo(hApplication,"test",&fileAttribute);
    ret = FunctionList->SKF_GetFileInfo(hApplication,filename,&fileAttribute);
    if(ret) {
        PRINT_KDF_ERROR(ret);
        return ret;
    }
    printf("----Get File[%s] Info ----\n",filename);
    printf("FileName    : %s\n",fileAttribute.FileName);
    printf("FileSize    : %d\n",fileAttribute.FileSize);
    printf("---------------------------\n");
    return ret;

}

int write_file(char *filename,char *data,int offset,int len)
{
    u32 ret;
    //result = skf_writeFile(hApplication,"test",0,&bData,1);
    ret = FunctionList->SKF_WriteFile(hApplication,filename,offset,(u8 *)data,len);
    if(ret) {
        PRINT_KDF_ERROR(ret);
    }
    return ret;
}

int read_file(char *filename,int offset,int len,char *data)
{
    u32 ret;
    u32 ulData;
    ret = FunctionList->SKF_ReadFile(hApplication,filename,offset,len,(u8 *)data,&ulData);
    if(ret) {
        PRINT_KDF_ERROR(ret);
        return ret;
    }
    printf("read %s len %d\n",filename,ulData);
    return ret;
}

int del_file(char *filename)
{
    u32 ret;
    ret = FunctionList->SKF_DeleteFile(hApplication,filename);
    if(ret) {
        PRINT_KDF_ERROR(ret);
        return ret;
    }
    return ret;
}

int create_and_writefile(char *filename,char *savename)
{
    u32 ret = 0;
    FILE *fp = NULL;
    char data[4096]={0};
    u32 data_len = 0;
    fp = fopen(filename,"rb");

    if(fp == NULL) {
        printf("Open file [%s] Fail.\n",filename);
        return -1;
    }

    data_len = fread(data,1,4096,fp);
    if(data_len <=0 ) {
        printf("Read file [%s] Fail.\n",filename);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /*--------------*/
    ret = create_file(savename,data_len);
    if(ret == SAR_FILE_ALREADY_EXIST) {
        if(del_file(savename)){
            return-1;
        }
        if(create_file(savename,data_len)){
            return -1;

        }
    }


    if(write_file(savename,data,0,data_len)){
        return ret;
    }
    ret = get_file_info(savename);

    return ret;
}

int read_and_savefile(char *filename,char* savename)
{
    u32 ret ;
    u32 filesize;
    char data[4096] = {0};
    u32 data_len = 0;
    u32 ulData;
    FILE *fp = NULL;
    FILEATTRIBUTE fileAttribute;
    ret = FunctionList->SKF_GetFileInfo(hApplication,filename,&fileAttribute);
    if(ret) {
        PRINT_KDF_ERROR(ret);
        return ret;
    }
    filesize = fileAttribute.FileSize;

    while(data_len < filesize){
        ret = FunctionList->SKF_ReadFile(hApplication,filename,data_len,128,(u8 *)data+data_len,&ulData);
        if(ret) {
            PRINT_KDF_ERROR(ret);
            return ret;
        }
        data_len += ulData;
    }

    printf("Read [%s]  Total Size %d\n",filename,data_len);

    fp = fopen(savename,"wb");
    if(fp == NULL) {
        printf("ERROR on Open file %s\n",savename);
        return -1;
    }
    ret = fwrite(data,1,data_len,fp);
    fclose(fp);
    if(ret != data_len) {
        printf("May Write Faile Fail!\n");
        return -1;
    }


    return 0;
}



// china-core 侧测试程序程序
u32 ECC_ImportKeyAndCert(DEVHANDLE hDev, HCONTAINER hCont)
{
    u8 keypair[] = {
        //x
        0x19, 0x79, 0x5d, 0xf7, 0x01, 0xf3, 0x9d, 0x1f, 0xb2, 0x20, 0xc4, 0x5f, 0xa7, 0xfa, 0x4e, 0xbf,
        0xad, 0xd1, 0x70, 0x25, 0x37, 0xb9, 0x46, 0xcd, 0x3d, 0x48, 0x04, 0xb3, 0x7f, 0xbc, 0x3e, 0xa5,
        //y
        0x2b, 0x2c, 0xee, 0xd6, 0xcc, 0x04, 0x2b, 0x5b, 0xbb, 0x56, 0x8d, 0xed, 0x3b, 0x36, 0x73, 0xf2,
        0x88, 0xe1, 0x9c, 0xc4, 0x9a, 0xe3, 0xc3, 0x50, 0xd2, 0xb8, 0x09, 0x03, 0xd8, 0x6d, 0x91, 0x2c,
        //d
        0x3f, 0x91, 0x68, 0xe8, 0x6d, 0x2a, 0xac, 0xaa, 0x2c, 0x81, 0xd8, 0xba, 0x24, 0x9b, 0xc9, 0x5a,
        0x60, 0xe0, 0x47, 0x50, 0xa2, 0xee, 0xaa, 0x63, 0x26, 0x2b, 0x54, 0xc4, 0x75, 0x51, 0xb8, 0xdc
    };

    u8 cert[] = {
        0x30, 0x82, 0x03, 0x01, 0x30, 0x82, 0x02, 0xA7, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x12,
        0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF1, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55,
        0x01, 0x83, 0x75, 0x30, 0x7D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x43, 0x4E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x02, 0x47, 0x44, 0x31,
        0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x02, 0x53, 0x5A, 0x31, 0x10, 0x30, 0x0E,
        0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x07, 0x53, 0x41, 0x4E, 0x47, 0x46, 0x4F, 0x52, 0x31, 0x0C,
        0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x03, 0x53, 0x53, 0x4C, 0x31, 0x10, 0x30, 0x0E,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x07, 0x73, 0x61, 0x6E, 0x67, 0x66, 0x6F, 0x72, 0x31, 0x22,
        0x30, 0x20, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x13, 0x73,
        0x61, 0x6E, 0x67, 0x66, 0x6F, 0x72, 0x40, 0x73, 0x61, 0x6E, 0x67, 0x66, 0x6F, 0x72, 0x2E, 0x63,
        0x6F, 0x6D, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x35, 0x31, 0x30, 0x31, 0x32, 0x30, 0x38, 0x35, 0x37,
        0x34, 0x38, 0x5A, 0x17, 0x0D, 0x32, 0x35, 0x31, 0x30, 0x31, 0x31, 0x30, 0x38, 0x35, 0x37, 0x34,
        0x38, 0x5A, 0x30, 0x7D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43,
        0x4E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x02, 0x47, 0x44, 0x31, 0x0B,
        0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x02, 0x53, 0x5A, 0x31, 0x10, 0x30, 0x0E, 0x06,
        0x03, 0x55, 0x04, 0x0A, 0x13, 0x07, 0x53, 0x41, 0x4E, 0x47, 0x46, 0x4F, 0x52, 0x31, 0x0C, 0x30,
        0x0A, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x03, 0x53, 0x53, 0x4C, 0x31, 0x10, 0x30, 0x0E, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x13, 0x07, 0x73, 0x61, 0x6E, 0x67, 0x66, 0x6F, 0x72, 0x31, 0x22, 0x30,
        0x20, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x13, 0x73, 0x61,
        0x6E, 0x67, 0x66, 0x6F, 0x72, 0x40, 0x73, 0x61, 0x6E, 0x67, 0x66, 0x6F, 0x72, 0x2E, 0x63, 0x6F,
        0x6D, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
        0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, 0x03, 0x42, 0x00, 0x04, 0x19, 0x79, 0x5D, 0xF7,
        0x01, 0xF3, 0x9D, 0x1F, 0xB2, 0x20, 0xC4, 0x5F, 0xA7, 0xFA, 0x4E, 0xBF, 0xAD, 0xD1, 0x70, 0x25,
        0x37, 0xB9, 0x46, 0xCD, 0x3D, 0x48, 0x04, 0xB3, 0x7F, 0xBC, 0x3E, 0xA5, 0x2B, 0x2C, 0xEE, 0xD6,
        0xCC, 0x04, 0x2B, 0x5B, 0xBB, 0x56, 0x8D, 0xED, 0x3B, 0x36, 0x73, 0xF2, 0x88, 0xE1, 0x9C, 0xC4,
        0x9A, 0xE3, 0xC3, 0x50, 0xD2, 0xB8, 0x09, 0x03, 0xD8, 0x6D, 0x91, 0x2C, 0xA3, 0x82, 0x01, 0x0F,
        0x30, 0x82, 0x01, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30,
        0x2C, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x0D, 0x04, 0x1F, 0x16, 0x1D,
        0x4F, 0x70, 0x65, 0x6E, 0x53, 0x53, 0x4C, 0x20, 0x47, 0x65, 0x6E, 0x65, 0x72, 0x61, 0x74, 0x65,
        0x64, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x30, 0x1D, 0x06,
        0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x50, 0x30, 0xB3, 0x89, 0x44, 0xF0, 0xB5, 0x9B,
        0x21, 0xA1, 0xCF, 0xC6, 0xE3, 0x80, 0xF0, 0xD5, 0x4D, 0xE5, 0x22, 0x25, 0x30, 0x81, 0xB0, 0x06,
        0x03, 0x55, 0x1D, 0x23, 0x04, 0x81, 0xA8, 0x30, 0x81, 0xA5, 0x80, 0x14, 0xEC, 0x25, 0x01, 0xB6,
        0x82, 0x08, 0xE1, 0xC3, 0xDF, 0x2D, 0x8D, 0x0B, 0xD6, 0xB5, 0x49, 0x4C, 0x05, 0x8F, 0x32, 0x14,
        0xA1, 0x81, 0x81, 0xA4, 0x7F, 0x30, 0x7D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
        0x13, 0x02, 0x43, 0x4E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x02, 0x47,
        0x44, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x02, 0x53, 0x5A, 0x31, 0x10,
        0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x07, 0x53, 0x41, 0x4E, 0x47, 0x46, 0x4F, 0x52,
        0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x03, 0x53, 0x53, 0x4C, 0x31, 0x10,
        0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x07, 0x73, 0x61, 0x6E, 0x67, 0x66, 0x6F, 0x72,
        0x31, 0x22, 0x30, 0x20, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16,
        0x13, 0x73, 0x61, 0x6E, 0x67, 0x66, 0x6F, 0x72, 0x40, 0x73, 0x61, 0x6E, 0x67, 0x66, 0x6F, 0x72,
        0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x09, 0x00, 0x9D, 0x1D, 0x78, 0xA7, 0x1F, 0xAC, 0xEE, 0xA3, 0x30,
        0x0A, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75, 0x03, 0x48, 0x00, 0x30, 0x45,
        0x02, 0x21, 0x00, 0xAF, 0x31, 0xCD, 0x66, 0xB9, 0x81, 0x85, 0x34, 0x17, 0xC3, 0x75, 0x6B, 0xE6,
        0xFA, 0x5F, 0xD6, 0x57, 0x94, 0xC2, 0x2A, 0x31, 0xB3, 0x06, 0xC1, 0x84, 0xB6, 0xDC, 0x64, 0xF1,
        0x47, 0x50, 0x42, 0x02, 0x20, 0x3F, 0xE1, 0x92, 0x66, 0x2A, 0xCB, 0xD2, 0x9D, 0xBE, 0x89, 0x99,
        0x98, 0x7E, 0xA2, 0x57, 0xB8, 0x65, 0xCB, 0x61, 0xE7, 0xC3, 0xD5, 0x8D, 0x08, 0xC5, 0xB3, 0x9D,
        0x3E, 0x59, 0x27, 0xB6, 0x5F
    };


    ULONG ret, len = 128;
    ECCPUBLICKEYBLOB pub;
    HANDLE hKey;
    BLOCKCIPHERPARAM bp;
    u8 encryptkey[1024];
    u8 key[16] = {0x47, 0x50, 0x42, 0x02, 0x20, 0x3F, 0xE1, 0x92, 0x66, 0x2A, 0xCB, 0xD2, 0x9D, 0, 0, 0};
    PENVELOPEDKEYBLOB env = (PENVELOPEDKEYBLOB)encryptkey;

    bp.PaddingType = 0;
    bp.IVLen = 0;
    bp.FeedBitLen = 0;

    memset(encryptkey, 0 ,1024);

    env->Version = 1;
    env->ulBits = 256;
    env->PubKey.BitLen = 256;
    env->ulSymmAlgID = SGD_SM1_ECB;
    memcpy(env->PubKey.XCoordinate + 32, keypair, 32);
    memcpy(env->PubKey.YCoordinate + 32, keypair + 32, 32);

    len = 1024;
    ret = FunctionList->SKF_ExportPublicKey(hCont, 0, encryptkey, &len);
    if(ret == 0)//已经存在密钥不导入
        return 0;

    LOG("Use SIGN KEY public key encrypt a symmetric key first then use this symmetric key encrypt the ENCRYPT KEY \n");

    len = sizeof(ECCPUBLICKEYBLOB);
    ret = FunctionList->SKF_ExportPublicKey(hCont, 1, (u8*)&pub, &len);
    if(ret)
    {
        if(ret == SAR_KEYNOTFOUNTERR)
        {
            ret = FunctionList->SKF_GenECCKeyPair(hCont, SGD_SM2_1, &pub);
            if(ret)
            {
                LOG("SKF_GenECCKeyPair for SIGN KEY error : 0x%x\n", ret);
                return ret;
            }
        }
        else
        {
            LOG("SKF_ExportPublicKey for SIGN KEY error : 0x%x\n", ret);
            return ret;
        }
    }
#if 1
    ret = FunctionList->SKF_ExtECCEncrypt(hDev, &pub, key, 16, &env->ECCCipherBlob);
    if(ret)
    {
        LOG("SKF_ExtECCEncrypt error : 0x%x\n", ret);
        return ret;
    }
    ret = FunctionList->SKF_SetSymmKey(hDev, key, SGD_SM1_ECB, &hKey);
    if(ret)
    {
        LOG("SKF_SetSymmKey error : 0x%x\n", ret);
        return ret;
    }
#else
    ret = SKF_ECCExportSessionKey(hCont, SGD_SM1_ECB, &pub, &env->ECCCipherBlob, &hKey);
    if(ret)
    {
        LOG("SKF_ECCExportSessionKey error : 0x%x\n", ret);
        return ret;
    }

    ret = SKF_ImportSessionKey(hCont, SGD_SM1_ECB, (u8*)&env->ECCCipherBlob, sizeof(ECCCIPHERBLOB) + env->ECCCipherBlob.CipherLen - 1, &hKey);
    if(ret)
    {
        LOG("SKF_ImportSessionKey error : 0x%x\n", ret);
        return ret;
    }
#endif
    ret = FunctionList->SKF_EncryptInit(hKey, bp);
    if(ret)
    {
        LOG("SKF_EncryptInit error : 0x%x\n", ret);
        return ret;
    }

    len = 32;
    ret = FunctionList->SKF_Encrypt(hKey, keypair + 64, 32, env->cbEncryptedPriKey + 32, &len);
    if(ret)
    {
        LOG("SKF_Encrypt error : 0x%x\n", ret);
        return ret;
    }

    ret = FunctionList->SKF_ImportECCKeyPair(hCont, env);
    if(ret)
    {
        LOG("SKF_ImportECCKeyPair error : 0x%x\n", ret);
        return ret;
    }

    ret = FunctionList->SKF_ImportCertificate(hCont, 0, cert, sizeof(cert));
    if(ret)
    {
        LOG("SKF_ImportCertificate error : 0x%x\n", ret);
        return ret;
    }

    return 0;
}







//DEVHANDLE* devHandle;                   //操作句柄
//HCONTAINER hContainer;                  //容器
u32 import_sm2_cert()
{
    u32 ret ;

    ret =ECC_ImportKeyAndCert(*devHandle,hContainer);
    if(ret){
        PRINT_KDF_ERROR(ret);
    }

}
