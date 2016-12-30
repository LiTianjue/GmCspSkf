#include "include/skf_err_string.h"

typedef struct {
    int err_no;
    char *err_string;
} skf_errinfo;

skf_errinfo skf_errstr_en[] = {
    { SAR_OK,			"Success" },
    { SAR_FAIL,			"Failure" },
    { SAR_UNKNOWNERR,		"Unknown error" },
    { SAR_NOTSUPPORTYETERR,		"Not supported" },
    { SAR_FILEERR,			"File error" },
    { SAR_INVALIDHANDLEERR,		"Invalid handle" },
    { SAR_INVALIDPARAMERR,		"Invalid parameter" },
    { SAR_READFILEERR,		"Read file error" },
    { SAR_WRITEFILEERR,		"Write file error" },
    { SAR_NAMELENERR,		"Name length error" },
    { SAR_KEYUSAGEERR,		"Key usage error" },
    { SAR_MODULUSLENERR,		"Modulus length error" },
    { SAR_NOTINITIALIZEERR,		"Not initialized" },
    { SAR_OBJERR,			"Object error" },
    { SAR_MEMORYERR,		"Memory error" },
    { SAR_TIMEOUTERR,		"Time out" },
    { SAR_INDATALENERR,		"Input data length error" },
    { SAR_INDATAERR,		"Input data error" },
    { SAR_GENRANDERR,		"Generate randomness error" },
    { SAR_HASHOBJERR,		"Hash object error" },
    { SAR_HASHERR,			"Hash error" },
    { SAR_GENRSAKEYERR,		"Genenerate RSA key error" },
    { SAR_RSAMODULUSLENERR,		"RSA modulus length error" },
    { SAR_CSPIMPRTPUBKEYERR,	"CSP import public key error" },
    { SAR_RSAENCERR,		"RSA encryption error" },
    { SAR_RSADECERR,		"RSA decryption error" },
    { SAR_HASHNOTEQUALERR,		"Hash not equal" },
    { SAR_KEYNOTFOUNTERR,		"Key not found" },
    { SAR_CERTNOTFOUNTERR,		"Certificate not found" },
    { SAR_NOTEXPORTERR,		"Not exported" },
    { SAR_DECRYPTPADERR,		"Decrypt pad error" },
    { SAR_MACLENERR,		"MAC length error" },
    { SAR_BUFFER_TOO_SMALL,		"Buffer too small" },
    { SAR_KEYINFOTYPEERR,		"Key info type error" },
    { SAR_NOT_EVENTERR,		"No event error" },
    { SAR_DEVICE_REMOVED,		"Device removed" },
    { SAR_PIN_INCORRECT,		"PIN incorrect" },
    { SAR_PIN_LOCKED,		"PIN locked" },
    { SAR_PIN_INVALID,		"PIN invalid" },
    { SAR_PIN_LEN_RANGE,		"PIN length error" },
    { SAR_USER_ALREADY_LOGGED_IN,	"User already logged in" },
    { SAR_USER_PIN_NOT_INITIALIZED,	"User PIN not initialized" },
    { SAR_USER_TYPE_INVALID,	"User type invalid" },
    { SAR_APPLICATION_NAME_INVALID, "Application name invalid" },
    { SAR_APPLICATION_EXISTS,	"Application already exist" },
    { SAR_USER_NOT_LOGGED_IN,	"User not logged in" },
    { SAR_APPLICATION_NOT_EXISTS,	"Application not exist" },
    { SAR_FILE_ALREADY_EXIST,	"File already exist" },
    { SAR_NO_ROOM,			"No file space" },
    { SAR_FILE_NOT_EXIST,		"File not exist" }
};


skf_errinfo skf_errstr_cn[] = {
    { SAR_OK                         ," 成功"},
    { SAR_FAIL                       ," 失败"},
    { SAR_UNKNOWNERR                 ," 异常错误"},
    { SAR_NOTSUPPORTYETERR           ," 不支持的服务"},
    { SAR_FILEERR                    ," 文件操作错误"},
    { SAR_INVALIDHANDLEERR           ," 无效的句柄"},
    { SAR_INVALIDPARAMERR            ," 无效的参数"},
    { SAR_READFILEERR                ," 读文件错误"},
    { SAR_WRITEFILEERR               ," 写文件错误"},
    { SAR_NAMELENERR                 ," 名称长度错误"},
    { SAR_KEYUSAGEERR                ," 密钥用途错误"},
    { SAR_MODULUSLENERR              ," 模的长度错误"},
    { SAR_NOTINITIALIZEERR           ," 未初始化" },
    { SAR_OBJERR                     ," 对象错误" },
    { SAR_MEMORYERR                  ," 内存错误" },
    { SAR_TIMEOUTERR                 ," 超时" },
    { SAR_INDATALENERR               ," 输入数据长度错误" },
    { SAR_INDATAERR                  ," 输入数据错误" },
    { SAR_GENRANDERR                 ," 生成随机数错误" },
    { SAR_HASHOBJERR                 ," HASH 对象错" },
    { SAR_HASHERR                    ," HASH 运算错误 " },
    { SAR_GENRSAKEYERR               ," 产生 RSA 密钥错 " },
    { SAR_RSAMODULUSLENERR           ," RSA 密钥模长错误" },
    { SAR_CSPIMPRTPUBKEYERR          ," CSP 服务导入公钥错误" },
    { SAR_RSAENCERR                  ," RSA 加密错误" },
    { SAR_RSADECERR                  ," RSA 解密错误" },
    { SAR_HASHNOTEQUALERR            ," HASH 值不相等" },
    { SAR_KEYNOTFOUNTERR             ," 密钥未发现 " },
    { SAR_CERTNOTFOUNTERR            ," 证书未发现 " },
    { SAR_NOTEXPORTERR               ," 对象未导出 " },
    { SAR_DECRYPTPADERR              ," 解密时做补丁错误 " },
    { SAR_MACLENERR                  ," MAC 长度错误 " },
    { SAR_BUFFER_TOO_SMALL           ," 缓冲区不足 " },
    { SAR_KEYINFOTYPEERR             ," 密钥类型错误 " },
    { SAR_NOT_EVENTERR               ," 无事件错误 " },
    { SAR_DEVICE_REMOVED             ," 设备已移除 " },
    { SAR_PIN_INCORRECT              ," PIN 不正确 " },
    { SAR_PIN_LOCKED                 ," PIN 被锁死 " },
    { SAR_PIN_INVALID                ," PIN 无效 " },
    { SAR_PIN_LEN_RANGE              ," PIN 长度错误 " },
    { SAR_USER_ALREADY_LOGGED_IN     ," 用户已经登录 " },
    { SAR_USER_PIN_NOT_INITIALIZED   ," 没有初始化用户口令 " },
    { SAR_USER_TYPE_INVALID          ," PIN 类型错误 " },
    { SAR_APPLICATION_NAME_INVALID   ," 应用名称无效 " },
    { SAR_APPLICATION_EXISTS         ," 应用已经存在 " },
    { SAR_USER_NOT_LOGGED_IN         ," 用户没有登录 " },
    { SAR_APPLICATION_NOT_EXISTS     ," 应用不存在 " },
    { SAR_FILE_ALREADY_EXIST         ," 文件已经存在 " },
    { SAR_NO_ROOM                    ," 空间不足 " },
    { SAR_FILE_NOT_EXIST             ," 文件不存在 " },
    { SAR_REACH_MAX_CONTAINER_COUNT  ," 已达到最大可管理容器数" }
};

char *SKF_get_errstr_cn(int ulError){

    int i;
    for(i = 0; i < sizeof(skf_errstr_cn)/sizeof(skf_errstr_cn[0]);i++) {
        if(ulError == skf_errstr_cn[i].err_no)
            return skf_errstr_cn[i].err_string;
    }

    return "(undef)";
}

char *SKF_get_errstr_en(int ulError){

    int i;
    for(i = 0; i < sizeof(skf_errstr_en)/sizeof(skf_errstr_en[0]);i++) {
        if(ulError == skf_errstr_en[i].err_no)
            return skf_errstr_en[i].err_string;
    }

    return "(undef)";
}








