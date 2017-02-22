#include <jni.h>
#include <string>
#include <stdio.h>
#include "inject.h"
extern "C" jstring
Java_com_mixi_injectdemo_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    int pid = start();
    std::string hello = "Hello from C++";
    char buffer[5];
    sprintf(buffer,"%d",pid);
    return env->NewStringUTF(hello.append(buffer).c_str());
}
