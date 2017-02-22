//
// Created by mixi on 2016/9/28.
//

#ifndef INJECTDEMO_INJECT_H
#define INJECTDEMO_INJECT_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

int start();
#ifdef __cplusplus
}
#endif
struct inject_param_t{
    //进程的PID
    pid_t from_pid;
};



#endif //INJECTDEMO_INJECT_H
