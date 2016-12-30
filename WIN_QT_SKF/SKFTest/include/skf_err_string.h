#ifndef SKF_ERR_STRING_H
#define SKF_ERR_STRING_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>

char *SKF_get_errstr_cn(int ulError);
char *SKF_get_errstr_en(int ulError);
#define LANGE_EN    1

#define skf_str(v) #v

#ifdef LAGNE_CN
#define PRINT_KDF_ERROR(rv) \
    fprintf(stderr,"[KDF ERROR] [%s]: %s\n",__FUNCTION__,SKF_get_errstr_cn(rv))
#else
#define PRINT_KDF_ERROR(rv) \
    fprintf(stderr,"[KDF ERROR] [%s]: %s\n",__FUNCTION__,SKF_get_errstr_en(rv))
#endif



//设备状态错误码
#define  DEV_ABSENT_STATE 	0x00000000 	//设备不存在
#define  DEV_PRESENT_STATE 	0x00000001 	//设备存在
#define  DEV_UNKNOW_STATE 	0x00000002 	//设备状态未知

//安全权限状态
#define SECURE_NEVER_ACCOUNT    0x00000000    //不允许
#define SECURE_ADM_ACCOUNT 	    0x00000001    //管理员权限
#define SECURE_USER_ACCOUNT 	0x00000010    //用户权限
#define SECURE_ANYONE_ACCOUNT 	0x000000FF    //任何人

//容器类型
#define CONTAINER_TYPE_NONE      0   // 未定
#define CONTAINER_TYPE_RSA       1   // RSA
#define CONTAINER_TYPE_ECC       2   // ECC

//证书类型
//[IN] TRUE表示签名证书，FALSE表示加密证书。
#define CERT_TYPE_SIGN          1
#define CERT_TYPE_ENC           0


//错误码表
#define SAR_OK                         0x00000000    // 成功
#define SAR_FAIL                       0x0A000001    // 失败
#define SAR_UNKNOWNERR                 0x0A000002    // 异常错误
#define SAR_NOTSUPPORTYETERR           0x0A000003    // 不支持的服务
#define SAR_FILEERR                    0x0A000004    // 文件操作错误
#define SAR_INVALIDHANDLEERR           0x0A000005    // 无效的句柄
#define SAR_INVALIDPARAMERR            0x0A000006    // 无效的参数
#define SAR_READFILEERR                0x0A000007    // 读文件错误
#define SAR_WRITEFILEERR               0x0A000008    // 写文件错误
#define SAR_NAMELENERR                 0x0A000009    // 名称长度错误
#define SAR_KEYUSAGEERR                0x0A00000A    // 密钥用途错误
#define SAR_MODULUSLENERR              0x0A00000B    // 模的长度错误
#define SAR_NOTINITIALIZEERR           0x0A00000C    // 未初始化
#define SAR_OBJERR                     0x0A00000D    // 对象错误
#define SAR_MEMORYERR                  0x0A00000E    // 内存错误
#define SAR_TIMEOUTERR                 0x0A00000F    // 超时
#define SAR_INDATALENERR               0x0A000010    // 输入数据长度错误
#define SAR_INDATAERR                  0x0A000011    // 输入数据错误
#define SAR_GENRANDERR                 0x0A000012    // 生成随机数错误
#define SAR_HASHOBJERR                 0x0A000013    // HASH 对象错
#define SAR_HASHERR                    0x0A000014    // HASH 运算错误
#define SAR_GENRSAKEYERR               0x0A000015    // 产生 RSA 密钥错
#define SAR_RSAMODULUSLENERR           0x0A000016    // RSA 密钥模长错误
#define SAR_CSPIMPRTPUBKEYERR          0x0A000017    // CSP 服务导入公钥错误
#define SAR_RSAENCERR                  0x0A000018    // RSA 加密错误
#define SAR_RSADECERR                  0x0A000019    // RSA 解密错误
#define SAR_HASHNOTEQUALERR            0x0A00001A    // HASH 值不相等
#define SAR_KEYNOTFOUNTERR             0x0A00001B    // 密钥未发现
#define SAR_CERTNOTFOUNTERR            0x0A00001C    // 证书未发现
#define SAR_NOTEXPORTERR               0x0A00001D    // 对象未导出
#define SAR_DECRYPTPADERR              0x0A00001E    // 解密时做补丁错误
#define SAR_MACLENERR                  0x0A00001F    // MAC 长度错误
#define SAR_BUFFER_TOO_SMALL           0x0A000020    // 缓冲区不足
#define SAR_KEYINFOTYPEERR             0x0A000021    // 密钥类型错误
#define SAR_NOT_EVENTERR               0x0A000022    // 无事件错误
#define SAR_DEVICE_REMOVED             0x0A000023    // 设备已移除
#define SAR_PIN_INCORRECT              0x0A000024    // PIN 不正确
#define SAR_PIN_LOCKED                 0x0A000025    // PIN 被锁死
#define SAR_PIN_INVALID                0x0A000026    // PIN 无效
#define SAR_PIN_LEN_RANGE              0x0A000027    // PIN 长度错误
#define SAR_USER_ALREADY_LOGGED_IN     0x0A000028    // 用户已经登录
#define SAR_USER_PIN_NOT_INITIALIZED   0x0A000029    // 没有初始化用户口令
#define SAR_USER_TYPE_INVALID          0x0A00002A    // PIN 类型错误
#define SAR_APPLICATION_NAME_INVALID   0x0A00002B    // 应用名称无效
#define SAR_APPLICATION_EXISTS         0x0A00002C    // 应用已经存在
#define SAR_USER_NOT_LOGGED_IN         0x0A00002D    // 用户没有登录
#define SAR_APPLICATION_NOT_EXISTS     0x0A00002E    // 应用不存在
#define SAR_FILE_ALREADY_EXIST         0x0A00002F    // 文件已经存在
#define SAR_NO_ROOM                    0x0A000030    // 空间不足
#define SAR_FILE_NOT_EXIST             0x0A000031    // 文件不存在
#define SAR_REACH_MAX_CONTAINER_COUNT  0x0A000032    // 已达到最大可管理容器数









#endif // SKF_ERR_STRING_H
