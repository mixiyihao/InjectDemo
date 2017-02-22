//
// Created by mixi on 2016/10/9.
//
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <stdio.h>

#define SYS_write 1
#define R15 0
#define R14 1
#define R13 2
#define R12 3
#define RBP 4
#define RBX 5
#define R11 6
#define R10 7
#define R9 8
#define R8 9
#define RAX 10
#define RCX 11
#define RDX 12
#define RSI 13
#define RDI 14
#define ORIG_RAX 15
#define RIP 16
#define CS 17
#define EFLAGS 18
#define RSP 19
#define SS 20
#define FS_BASE 21
#define GS_BASE 22
#define DS 23
#define ES 24
#define FS 25
#define GS 26

int main(){
    pid_t child;
    long orig_eax,eax;
    long param[3];
    int status;
    int insyscall = 0;
    child = fork();
    if(child == 0){
        ptrace(PTRACE_TRACEME,child,0,0);
        execl("/bin/ls","ls",0);
    }else{
        while (1){
            wait(&status);
            if(WIFEXITED(status))
                break;
            orig_eax = ptrace(PTRACE_PEEKUSER,child,8*15,0);
            //x86 sys_write
            if(orig_eax == SYS_write){
                if(insyscall == 0){
                    insyscall =1;
                    param[0] = ptrace(PTRACE_PEEKUSER,child,8*RBX,0);
                    param[1] = ptrace(PTRACE_PEEKUSER,child,8*RCX,0);
                    param[2] = ptrace(PTRACE_PEEKUSER,child,8*RDX,0);
                    printf("write called withd rbx= %ld,rcx = %ld,rdx = %ld",param[0],param[1],param[2])

                }
            } else{
                eax = ptrace(PTRACE_PEEKUSER,child,8*RAX,0);
                printf("write return whith %d",eax);
                insyscall =0;
            }
            ptrace(PTRACE_SYSCALL,child,0,0);
        }

    }
    return 0;

}
