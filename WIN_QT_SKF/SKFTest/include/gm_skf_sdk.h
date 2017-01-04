#ifndef GM_SKF_SDK_H
#define GM_SKF_SDK_H


int init_skf_dll(char *dll);    //获取skf方法集合

int connect_device();           //连接设备

int get_device_state();         //获取设备状态

int open_application();         //打开应用，打开默认应用即可

int close_application();        //关闭应用

int open_container();           //打开容器

int get_container_type();       //获取容器类型





//写证书流程
//1. 加载动态库
//2. 连接设备
//3. 打开应用(使用默认应用)
//4. 打开容器(没有需要创建,存在需要删除？)
//5. 验证pin码？ (好像不是必须的)
//6. 读取私钥，构建数据结构
/*
    {
        x 分量，
        y 分量，
        d 私钥分量，
    }
*/
//7. 写入私钥
//8. 读取der编码的公钥证书文件
//9. 写入公钥证书



//读证书流程
//1. 加载动态库
//2. 连接设备
//3. 打开应用(使用默认应用)
//4. 打开容器(没有需要创建,存在需要删除？)
//5. 验证pin码？ (好像不是必须的)
//6. 读取der格式的公钥证书

#endif // GM_SKF_SDK_H
