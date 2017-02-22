LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -ldl -llog
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := inject
LOCAL_SRC_FILES := inject2.c
include $(BUILD_EXECUTABLE)
