//
// Created by mixi on 2016/10/11.
//

/**
 咪嘻 二次探索 inject  so
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>


#define LIBC_PATH  "/system/lib/libc.so"
#define LINKER_PATH "/system/bin/linker"

#define CPSR_T_MASK (1u<<5)
pid_t findTargeIdByName(const char *processName) {
    int id;
    DIR *dir;
    FILE *fp;
    pid_t pid = -1;//保存进程的PID
    char fileName[32];//保存进程名称
    char cmdline[32];//保存进程的命令进程，cmdline保存着进程的名字
    struct dirent *entry;
    if (processName == NULL) {
        return -1;
    }
    dir = opendir("/proc");
    if (dir == NULL) {
        printf("the open dir is error = %d\n", errno);
        return -1;
    }
    //循环读取/proc里面的文件
    while ((entry = readdir(dir)) != NULL) {
        //将文件字符转化为 int

        id = atoi(entry->d_name);
        if (id != 0) {
            //格式化字符串
            sprintf(fileName, "/proc/%d/cmdline", id);
            fp = fopen(fileName, "r");
            if (fp) {
                //获取文件的名字
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                //比较是否为进程的名称
                if (strcmp(processName, cmdline) == 0) {
                    pid = id;
                    break;
                }
            }
        }
    }
    closedir(dir);
    return pid;
}

/**
 跟踪子进程
 */
int attachPtrace(pid_t pid) {
    //跟踪进程将成为当前进程的子进程，并禁止终止状态
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        printf("ptrace attach defeat \n");
        return -1;
    }
    int status = 0;
    /*
     * WNOHANG
        告诉waitpid 不等程序终止立即返回status信息
        正常情况是当主进程对子进程使用了waitpid,主进程就会阻塞直到watipid返回status信息
        如果指定这个就是主进程不会阻塞了
     * */
    /**
     WUNTRACED
     告诉waitpid,如果子进程进入暂停状态或者已经终止，那么就立即返回statusxinxi ,
     正常情况是子进程终止的时候才返回，如果是被ptrace的子进程，那么即时不提供了

     */
    waitpid(pid, &status, WUNTRACED);
    return status;
}

/**
 * 获取寄存器里面的内容
 */
int ptrace_getregs(pid_t pid, struct pt_regs *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        printf("get regs error \n");
        return -1;
    }
    return 0;
}

/**
 获取进程中模块中的首地址
 */
void *getMoudleBase(int pid, const char *libPath) {
    char path[64];
    char lines[1024];
    char *pCh = NULL;
    long lBaseAddr = 0;
    if (pid == 0) {
        snprintf(path, sizeof(path), "/proc/self/maps");
    } else {
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    }
    FILE *fp = fopen(path, "r");
    if (fp != NULL) {
        while (fgets(lines, sizeof(lines), fp)) {
            if (strstr(lines, libPath)) {
                //拆分字符串
                pCh = strtok(lines, "-");
                //将字符串转化为数字
                lBaseAddr = strtoul(pCh, NULL, 16);
                break;
            }
        }
        fclose(fp);
        fp = NULL;
    }
    return (void *) lBaseAddr;
}

/**
 获取目标函数指针
 @param pid 目标进程pid
 @param libPath 进程的path
 @param libFuncAddr 函数内存地址
 目标进程中函数指针 = 目标进程模块基址 - 自身进程模块基址 + 内存地址
 */
void *getRemoteFunctionAddr(pid_t pid, const char *libPath, const char *libFuncAddr) {
    //进程模块基地址
    void *lpRemoteBaseAddr = getMoudleBase(pid, libPath);
    //自身模块基址
    void *lpLocalBaseAddr = getMoudleBase(0, libPath);
    void *lpRemoteFunctionAddr = NULL;
    if (lpLocalBaseAddr == NULL || lpRemoteBaseAddr == NULL) {
        return lpRemoteBaseAddr;
    }
    lpRemoteFunctionAddr = (void *) ((uint32_t) lpRemoteBaseAddr - (uint32_t) lpLocalBaseAddr +
                                     (uint32_t) libFuncAddr);
    return lpRemoteFunctionAddr;
}

/**
 向目标进程指定的地址写入数据
 @param pid 目标进程pid
 @param lpAddr 写入目标进程的地址
 @param lpData 写入数据缓冲区
 @param nLength 写入的数据长度
 */

int ptraceWriteProcessMemory(pid_t pid, void *lpAddr, uint8_t *lpData, uint32_t nLength) {
    uint32_t i, j, remain;
    uint8_t *lpDataBuff = NULL;
    union u {
        long val;
        char chars[sizeof(long)];
    } d;//联合体 4个字节char和long 使用同一个空间
    //4 个字节的整数倍
    j = nLength / 4;
    //剩余的字节数
    remain = nLength % 4;
    //data中存放的是要写入目标进程的数据
    lpDataBuff = lpData;
    for (i = 0; i < j; i++) {
        //拷贝4个字节
        memcpy(d.chars, lpDataBuff, 4);
        //向目标进程lpAddr写入一个长整型，
        ptrace(PTRACE_POKETEXT, pid, lpAddr, d.val);
        lpAddr += 4;
        lpDataBuff += 4;
    }

    //最后不足4个字节，进行单字节拷贝
    if (remain > 0) {
        //从目标进程中读取一个长整型，内存地址为lpAddr
        /*
         -------------------------------
         a0 a1 a2 a3 a4 a5 a6 a7
         --------------------------------
         0, 0, 0, 0, 0, 0, 0, 0
         --------------------------------
         为了防止后面还有数据，所以先读取long个字节，保留
          */
        d.val = ptrace(PTRACE_PEEKTEXT, pid, lpAddr, 0);
        //单字节拷贝
        for (i = 0; i < remain; i++) {
            d.chars[i] = *(lpDataBuff++);
        }
        printf("\n");
        //写入一个long 的东西
        //向目标进程写入剩余的数据
        ptrace(PTRACE_POKETEXT, pid, lpAddr, d.val);
    }
    return 0;
}
void printfRegs(struct pt_regs *regs){
    printf("-------------regs start--------------------\n");
    printf("ARM_cpsr = %ld\n",regs->ARM_cpsr);
    printf("ARM_pc = %ld\n",regs->ARM_pc);
    printf("ARM_lr = %ld\n",regs->ARM_lr);
    printf("ARM_sp = %ld\n",regs->ARM_sp);
    printf("ARM_ip = %ld\n",regs->ARM_ip);
    printf("ARM_fp = %ld\n",regs->ARM_fp);
    printf("ARM_r10 = %ld\n",regs->ARM_r10);
    printf("ARM_r9 = %ld\n",regs->ARM_r9);
    printf("ARM_r8 = %ld\n",regs->ARM_r8);
    printf("ARM_r7 = %ld\n",regs->ARM_r7);
    printf("ARM_r6 = %ld\n",regs->ARM_r6);
    printf("ARM_r5 = %ld\n",regs->ARM_r5);
    printf("ARM_r4 = %ld\n",regs->ARM_r4);
    printf("ARM_r3 = %ld\n",regs->ARM_r3);
    printf("ARM_r2 = %ld\n",regs->ARM_r2);
    printf("ARM_r1 = %ld\n",regs->ARM_r1);
    printf("ARM_r0 = %ld\n",regs->ARM_r0);
    printf("-------------regs end--------------------\n");
}

/**
  设置目标寄存器
  @param pid 目标进程pid
  @param regs 寄存器的值
 */
int ptraceSetRegs(pid_t pid, struct pt_regs *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
        return -1;
    }
    return 0;
}

/**
 回复目标寄存器

 */
int ptraceContinue(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        return -1;
    }
    return 0;
}
/**
 取消附加
 */
int ptraceDetach(pid_t pid){
    if(ptrace(PTRACE_DETACH,pid,NULL,NULL) == -1){
        return -1;
    }
    return 0;
}

/**
 调用远程函数指针
 调用远程函数指针
 @param nPid 注入进程的pid
 @param pfnFunctionAddr 调用函数指针的地址
 @param lpParamArg 参数
 @param paramCount 参数个数
 @param regs 远程进程寄存器信息 ARM 前4个参数由r0 - r3
 */
int ptraceCallRemoteFunction(pid_t nPid, void *pfnFunctionAddr, long *lpParamArg, int nParamCount,
                            struct pt_regs *regs) {
    uint32_t i = 0;
    int status = 0;
    /*
     arm 体系函数相互调用遵循的是ATPCS,它建议函数的形参不超过4个，
     如果<=4个 则可以直接存入 r0 ~ r3,如果超过4个了，那么将通过堆栈的形式进行传递
     */
    //前面四个参数复制给r0-r3

    for (; i < nParamCount && (i < 4); i++) {
        regs->uregs[i] = lpParamArg[i];
    }

    //剩余参数进行堆栈方式进行写入
    if (i < nParamCount) {
        //抬高栈顶sub esp,xxx
        regs->ARM_sp -= (nParamCount - i) * sizeof(long);
        ptraceWriteProcessMemory(nPid, (void *) regs->ARM_sp, (const uint8_t *)& lpParamArg[i],
                                 (uint32_t)((nParamCount - i) * sizeof(long)));
    }
    //将PC的值设置为函数地址
    regs->ARM_pc = pfnFunctionAddr;

    //设置ARM_cpsr寄存器的值
    if (regs->ARM_pc & 1) {
        //thumb
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        //arm
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }
    //设置返回地址为0,触发地址0异常回到当前进程中
    regs->ARM_lr = 0;
    //修改目标寄存器的值
    if (ptraceSetRegs(nPid, regs) == -1) {
        printf("set regs is defeat \n");
        return -1;
    }
    /*
     WUNTRACED 告诉 waitpid，如果子进程进入暂停状态，那么久立即返回。
     如果是被ptrace的子进程，那么即时不提供WUNTRACED参数，也会在子进程进入暂停状态的时候立即返回
     对于使用ptrace_cont 运行的子进程，它会在3中情况下进入暂停状态：
     1.下一次系统调用
     2.子进程退出
     3.子进程的执行发生错误
     oxb7f标识子进程进入了暂停状态，且发送的错误信号为11(SIGSEGV),它标识试图访问未分配给自己的内存，
     或试图往没有写权限的内存地址写入数据，
     当子进程执行完注入的函数后，由于我们在前面设置了regs->ARM_lr =0 ，它就会返回到0地址处继续执行
     这样就产生了（SIGSEGV）
     */
/*
    //在小米2s 5.0报错了 执行第二次ptraceContinue 导致错误
    //模拟器中5.0  status = 0xb7f
    do {
        printf("ptrace continue !!!!\n");
        if (ptraceContinue(nPid) == -1) {
            printf("ptrace continue error -1 \n");
            return -1;
        }

        waitpid(nPid, &status, WUNTRACED);

    } while (status != 0xb7f);
*/
    if (ptraceContinue(nPid) == -1) {
        printf("ptrace continue error -1 \n");
        return -1;
    }
    waitpid(nPid, &status, WUNTRACED);
    return 0;
}

/**
 调用远程函数指针
 @param pid 注入进程的pid
 @param lpFunctionName 调用的函数名称，此参数
 @param pfnFunctionAddr 调用函数指针的地址
 @param lpParamArg 参数
 @param paramCount 参数个数
 @param regs 远程进程寄存器信息 ARM 前4个参数由r0 - r3
 */
int callRemoteFunction(pid_t pid, const char *lpFunctionName, void *pfnFunctionAddr,
                       long *lpParamArg, int paramCount,
                       struct pt_regs *regs) {
    if(ptraceCallRemoteFunction(pid,pfnFunctionAddr,lpParamArg,paramCount,regs) == -1){
        printf("%s call remote defeat \n",lpFunctionName);
        return -1;
    }
    if(ptrace_getregs(pid,regs) == -1 ){
        printf("ptrace get regs defeat by remote function \n");
        return -1;
    }
    printfRegs(regs);
    return 0;
}

/**
 @param target_pid 需要注入进程的pid
 @param libary_path 需要注入的so路径
 @param function_name  需要注入的函数名称
 @param param 注入的函数参数
 @param param_size 参数的长度
 */
int inject_remote_process(pid_t target_pid, const char *libary_path, const char *function_name,
                          void *param, size_t param_size) {
    void *pfnmmap = NULL;
    void *pfndlopen = NULL;
    void *pfndlsym = NULL;
    void *pfndlclose = NULL;
    void *pMmapBase = NULL;
    struct pt_regs regs, old_regs;
    long paramArgs[10];
    void *pSo = NULL;
    void *pfnRemoteFunction = NULL;
    if (target_pid == -1) {
        printf("get the target_pid error value -1 \n");
        return -1;
    }
    //开始Attach附件进程
    if (attachPtrace(target_pid) == -1) {
        return -1;
    }

    printfRegs(&regs);
    if (ptrace_getregs(target_pid, &regs) == -1) {
        printf("get regs error -1\n");
        return -1;
    }
    //将老数据存储起来的 恢复使用
    memcpy(&old_regs, &regs, sizeof(regs));
    //获取mmap函数指针地址
    pfnmmap = getRemoteFunctionAddr(target_pid, LIBC_PATH, (void *) mmap);
    printf("the mmap addr=%x\n", pfnmmap);
    if (pfnmmap == NULL) {
        printf("get mmap defeat \n");
        return -1;
    }
    //申请远程空间参数
    //void* mmap(void* start,size_t length,int prot,int flags,int fd,off_t offset);
    paramArgs[0] = 0;
    paramArgs[1] = 0x4000;
    paramArgs[2] = PROT_READ | PROT_EXEC | PROT_WRITE;
    paramArgs[3] = MAP_ANONYMOUS | MAP_PRIVATE;
    paramArgs[4] = 0;
    paramArgs[5] = 0;
    if(callRemoteFunction(target_pid,"mmap",pfnmmap,paramArgs,6,&regs) == -1){
        printf("call remote function error -1 \n");
    }
    //远程申请的buffer首地址
    pMmapBase = regs.ARM_r0;
    printf(" 1 mmap the pMmapBase = %x, regs.ARM_r0 = %ld\n",pMmapBase,regs.ARM_r0);
    pfndlopen = getRemoteFunctionAddr(target_pid,LINKER_PATH,(void *)dlopen);
    pfndlsym = getRemoteFunctionAddr(target_pid,LINKER_PATH,(void *)dlsym);
    pfndlclose = getRemoteFunctionAddr(target_pid,LINKER_PATH,(void *)dlclose);
    if(pfndlopen == NULL || pfndlsym == NULL || pfndlclose == NULL){
        printf("error get remote function addr dlopen = %p ,dlsym = %p,dclose = %p \n",pfndlopen,pfndlsym,pfndlclose);
        return -1;
    }
    printf("success get remote function addr dlopen = %p ,dlsym = %p,dclose = %p \n",pfndlopen,pfndlsym,pfndlclose);
    //远程申请的Buffer首地址写入需要注入的so路径
    if(ptraceWriteProcessMemory(target_pid,pMmapBase,libary_path,strlen(libary_path) +1) == -1){
        printf("error write process memory by libary_path value -1 \n");
        return -1;
    }
    //调用dlopen void * dlopen(const char *pathName,int mode)
    paramArgs[0] = pMmapBase;
    paramArgs[1] = RTLD_NOW | RTLD_GLOBAL;
    printf(" 2 mmap the pMmapBase = %x \n",pMmapBase);
    if(callRemoteFunction(target_pid,"dlopen",pfndlopen,paramArgs,2,&regs) == -1){
        printf("error call remote function by dlopen \n");
        return -1;
    }
    pSo = regs.ARM_r0;
    printf("the regs.ARM_r0 = %p  value = %ld\n",pSo,regs.ARM_r0);
    //传递参数，准备调用 void *dlsym(void *handle,const char*name)
    paramArgs[0] = pSo;
#define FUNCTION_NAME_OFFSET 0x100
    if(ptraceWriteProcessMemory(target_pid,pMmapBase + FUNCTION_NAME_OFFSET,function_name,strlen(function_name) +1) == -1) {
        printf("error write process memory by function name \n");
        return -1;
    }
    paramArgs[1] = (long)pMmapBase + FUNCTION_NAME_OFFSET;
    if(callRemoteFunction(target_pid,"dlsym",pfndlsym,paramArgs,2,&regs) == -1){
        printf("error call remote function by dlsym");
        return -1;
    }
    pfnRemoteFunction = regs.ARM_r0;
    printf("the dlsym function adddr = %p, value = %ld\n",pfnRemoteFunction,regs.ARM_r0);
#define FUNCTION_PARAM_OFFSET 0x200

    if(ptraceWriteProcessMemory(target_pid,pMmapBase + FUNCTION_PARAM_OFFSET,paramArgs,strlen(paramArgs)+1) == -1){
        printf("error write process memory by param args value -1\n");
        return -1;
    }
    paramArgs[0] = pMmapBase + FUNCTION_PARAM_OFFSET;
    if(callRemoteFunction(target_pid,"hook_entry",pfnRemoteFunction,paramArgs,1,&regs) == -1){
        printf("error write the memory by hook_entry \n");
        return -1;
    }
    printf("-----------------------please entre to dlclose and detach--------------------- \n");
    getchar();
    paramArgs[0] = pSo;
    callRemoteFunction(target_pid,"dlclose",pfndlclose,paramArgs,1,&regs);
    printf("dclose success!!!!\n");
    ptraceSetRegs(target_pid,&old_regs);
    ptraceDetach(target_pid);
    printf("==================================--------success-------=========================");
    return 0;
}

int main() {
    //要注入进程的PID
    pid_t target_pid;
    //查找要注入的目标进程"/system/bin/servicemanager"的pid
    target_pid = findTargeIdByName("/system/bin/surfaceflinger");
    //对目标进程的servicemanager进行LibInject和函数Hook
    //"/data/local/tmp/libhookdll.so" 为注入到目标进程的so库
    //"hook_entry" 为注入调用的so库中的函数
    const char *say = "I am mixi";
    printf("target_pid = %d" ,target_pid);
    inject_remote_process(target_pid, "/data/local/tmp/mixi.so", "hook_entry", say, 11);
    return target_pid;
}
int start(){

}

