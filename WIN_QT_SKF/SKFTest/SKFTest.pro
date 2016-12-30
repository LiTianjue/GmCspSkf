TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    test.cpp \
    skf_errstr.cpp

DISTFILES += \
    lib/SKF_sd.dll

HEADERS += \
    include/base_type.h \
    include/SKF.h \
    include/skf_type.h \
    include/xchar.h \
    include/skf_err_string.h

#QMAKE_CXXFLAGS += -fpermissive
