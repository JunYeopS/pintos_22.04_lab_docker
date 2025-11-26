#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#define STDIN_SENTINEL  ((struct file *) 1)
#define STDOUT_SENTINEL ((struct file *) 2)

#endif /* userprog/syscall.h */
