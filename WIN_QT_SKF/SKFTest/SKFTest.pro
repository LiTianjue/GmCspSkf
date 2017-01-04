TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    test.cpp \
    skf_errstr.cpp \
    openssl_helper.cpp

DISTFILES += \
    lib/SKF_sd.dll

HEADERS += \
    include/base_type.h \
    include/SKF.h \
    include/skf_type.h \
    include/xchar.h \
    include/skf_err_string.h \
    include/openssl_helper.h \
    include/test_key.h \
    include/gm_skf_sdk.h


#add for openssl use
LIBS += -LC:/OpenSSL-Win32/lib/MinGw -leay32 -lssleay32
INCLUDEPATH += C:/OpenSSL-Win32/include/

#QMAKE_CXXFLAGS += -fpermissive
