
//
// Created by mixi on 2016/9/28.
//

/**
 ===========================
 咪嘻的学习注入代码啊 之一 哈哈
 ===========================
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include "inject.h"
//#include "../../../../../../developersoft/android-sdk-windows-new02/ndk-bundle/platforms/android-21/arch-arm/usr/include/asm/ptrace.h"
#include <errno.h>
//查找要注入的目标进程的PID

/**
 * @process_name 目标进程的名字
 */

int find_pid_of(const char *process_name){
    int id;
    DIR *dir;
    FILE *fp;
    pid_t  pid = -1;//保存进程的PID
    char fileName[32];//保存进程名称
    char cmdline[32];//保存进程的命令进程，cmdline保存着进程的名字
    struct dirent *entry;
    if(process_name == NULL){
        return -1;
    }
    dir = opendir("/proc");
    if(dir == NULL){
        printf("the open dir is error = %d\n",errno);
        return -1;
    }
    //循环读取/proc里面的文件
    while((entry = readdir(dir)) != NULL){
        //将文件字符转化为 int
        id = atoi(entry->d_name);
        if(id != 0){
            //格式化字符串
            sprintf(fileName,"/proc/%d/cmdline",id);
            fp = fopen(fileName,"r");
            if(fp){
                //获取文件的名字
                fgets(cmdline, sizeof(cmdline),fp);
                fclose(fp);
                //比较是否为进程的名称
                if(strcmp(process_name,cmdline) == 0){
                    pid = id;
                    break;
                }
            }
        }
    }
    closedir(dir);
    return pid;
}
//附加远程进程
/*int ptrace_attach(pid_t pid){
    //附加目标进程
    if(ptrace(16,pid,NULL,0) <0){
        return -1;
    }
    //等待目标进程附加完成
    waitpid(pid,NULL,0x00000002);
    //目标进程继续执行，让目标进程在下次进/出系统调用时被调试
    if (ptrace(23,pid,NULL,0)<0){
        perror("ptrace_syscall");
        return -1;
    }
    waitpid(pid,NULL,0x00000002);
    return 0;
}*/
//获取被附加调试进程的寄存器的值
/*int ptrace_getregs(pid_t pid,struct  pt_regs *regs){
    if(ptrace(12,pid,NULL,regs) <0){
        perror("ptrace get regs error");
        return -1;
    }
    return 0;
}*/

/**

 获取进程加载模块的基址

 */

/*void * get_module_base(pid_t pid,const char*module_name){
    FILE *fp;
    long addr = 0;
    char *pch;
    //保存模块的名称
    char filename[32];
    //保存读取的信息
    char line[1024];
    if(pid < 0){
        //获取当前进程的模块的基址
        snprintf(filename, sizeof(filename),"/proc/self/maps",pid);
    }else{
        //获取其他进程模块的基址
        snprintf(filename, sizeof(filename),"/proc/%d/maps",pid);
    }
    //root 权限
    fp = fopen(filename,"r");
    if(fp != NULL){
        //循环读取/proc/pid/maps 文件的信息每次一行
        while(fgets(line, sizeof(line),fp)){
            if(strstr(line,module_name)){
                //以 - 为标记拆分字符串
               pch =  strtok(line,"-");
                //字符串转无符号长整型的模块基址
                addr = strtoul(pch,NULL,16);
                //排除特殊情况
                if(addr == 0x8000){
                    addr = 0;
                }
                break;
            }
        }
        fclose(fp);
    }
    return (void *)addr;
}*/

/**
 获取其他进程的某加载模块中的某系统函数的调用地址
 一旦我们知道在我们的过程和目标过程中的一个给定的库的基本地址，
 我们可以做什么来解决远程功能的地址是：
    REMOTE_ADDRESS  = LOCAL_ADDRESS + (REMOTE_BASE - LOCAL_BASE)
 */


/*void * get_remote_addr(pid_t targe_pid,const char * module_name,void *local_addr){
    void *local_handler,*remote_handler;
    //获取某系统模块在当前进程中的加载基址
    local_handler = get_module_base(-1,module_name);
    //获取其他进程（目标进程）中某系统模块的加载基址
    remote_handler = get_module_base(targe_pid,module_name);
    printf("get remote addr:local[%x],remote[%x]",local_handler,remote_handler);
    return (void *)((uintptr_t)local_addr+(uintptr_t)remote_handler-(uintptr_t)local_handler);
}*/

/**
 * 在其他进程（远程目标进程）中调用系统函数mmap申请内存空间
 * void *mmap(void* start,size_t length,int prot,int flags,int fd,off_t offset)
 * @param params 是已经格式化的的mmap函数的参数，
 * @param num_params 是mmap函数的参数的个数
 * @param regs 是远程目标进程的寄存器的数据，
 * @param addr 为远程目标进程函数mmap的调用地址
 *
 */

/*int ptrace_call(pid_t pid,uint32_t addr,long *params,uint32_t num_params, struct pt_regs *regs){
    uint32_t  i;
    //ARM中函数mmap的前4个参数通过r0-r3来传入
    for(i =0;i<num_params && i<4;i++){
        regs->uregs[i] = params[i];
    }
    if(i<num_params){
        //ARM_sp = uregs[13]
        regs->uregs[13] -= (num_params -i)* sizeof(long);
    }
}*/




/**
 * 对远程目标进程进行LibInject和函数Hook
 * @param target_pid 进程目标pid
 * @param libary_path 自定义的Hook函数所在的模块(libHook.so)的路径
 * @param function_name 函数libHook.so库中名称Hook_Api
 * @param param Hook函数所需要的参数
 * @param param_size 函数调用的所需要的参数大小
 */

/*int inject_remote_process(pid_t target_pid, const char *libary_path,const char*function_name,void *param,size_t param_size)
{
    int ret = -1;
    void *mmap_addr,*dlopen_addr,*dlsym_addr,*dlclose_addr;
    void *local_handle,*remote_handle,*dlhandle;
    uint8_t *map_base;
    uint8_t *dlopen_param1_ptr,*dlsym_param2_ptr,*save_r0_pc_ptr,*inject_param_ptr,*remote_code_ptr,*local_code_ptr;
    struct pt_regs regs,original_regs;
    //导出全局变量
    extern uint32_t  _dlopen_addr_s,_dlopen_param1_s,_dlopen_param2_s,_dlsym_addr,_dlsym_param2_s,_dlclose_addr_s,_inject_start_s,_inject_end_s,_inject_function_param_s,_saved_cpsr_s,_savad_r0_pc_s;
    uint32_t code_length;
    long parameters[10];
    printf("injecting process:%d\n",target_pid);
    //附加远程目标进程
    if(ptrace_attach(target_pid) == -1){
        printf("the ptrace attach target defeat");
        return -1;
    }
    //获取护甲远程目标进程此时寄存器的状态值
    if(ptrace_getregs(target_pid,&regs) == -1){
        printf("get the regs defeat ");
    }
    //保存获取到的附加目标进程的寄存器的状态值
    memcpy(&original_regs,&regs, sizeof(regs));
    //获取附加远程目标进程"/system/lib/libc.so"模块中函数mmap的调用地址
    mmap_addr = get_remote_addr(target_pid,libary_path,(void *)mmap);//system/lib/libc
    parameters[0] = 0;//addr
    parameters[1] = 0x4000;//size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;//prot
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE;//flags
    parameters[4] = 0;//fd
    parameters[5] = 0;//offset
    printf("calling mmap in target process .\n");
    //在附加远程目标进程中调用函数mmap申请内存空间

}*/
//入口函数
/*
 int main(int argc,char **argv){
    //要注入进程的PID
    pid_t target_pid;
    //查找要注入的目标进程"/system/bin/servicemanager"的pid
    target_pid = find_pid_of("/system/bin/surfaceflinger");
    //对目标进程的servicemanager进行LibInject和函数Hook
    //"/data/local/tmp/libhookdll.so" 为注入到目标进程的so库
    //"hook_entry" 为注入调用的so库中的函数
    char * say ="I am mixi";
    inject_remote_process(target_pid,"/data/local/tmp/libhookdll.so","hook_entry",say,strlen(say));


}
 */
int start(){
    //要注入进程的PID
    pid_t target_pid;
    //查找要注入的目标进程"/system/bin/servicemanager"的pid
    target_pid = find_pid_of("/system/bin/surface");
    //对目标进程的servicemanager进行LibInject和函数Hook
    //"/data/local/tmp/libhookdll.so" 为注入到目标进程的so库
    //"hook_entry" 为注入调用的so库中的函数
    const char * say ="I am mixi";
    return target_pid;
}

