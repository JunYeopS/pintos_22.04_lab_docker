#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct fork_aux_arg {
    struct thread *parent;          
    struct intr_frame parent_if;    // 부모의 intr_frame 
    struct semaphore fork_sema;          // 부모를 깨울 세마포어
    bool success;                    // 자식 초기화 성공 여부
};

struct child_info;

struct child_info {
    tid_t tid;                 
    int exit_status;           /*자식의 exit(status)*/
    bool is_exited;            /* 자식이 정말로 종료됐는지 */
    bool waited;
    struct semaphore wait_sema;     /* 부모를 잠재우고 깨울 세마포어 */
    struct list_elem elem;     
};


tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

#endif /* userprog/process.h */
