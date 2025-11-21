#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h" // for PGSIZE
#include "userprog/process.h"
struct lock filesys_lock;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void sys_exit (int status);
void sys_halt (void);
int sys_write (int fd, const void *buffer, unsigned length);
bool sys_create (char *file, unsigned initial_size);
static void check_user_str(char *str);
int sys_open(char *file);
void sys_close (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_filesize (int fd);
int sys_write (int fd, const void *buffer, unsigned size);

#define FD_CAP (PGSIZE / sizeof(struct file *))

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init (&filesys_lock); // lock 초기화 
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	uint64_t sys_num = f->R.rax;

	switch (sys_num){
		case SYS_HALT:
			sys_halt();
			break;
		case SYS_EXIT:
			sys_exit(f->R.rdi);
			break;
		case SYS_FORK:{
			const char *thread_name = f->R.rdi;
			f->R.rax = process_fork(thread_name, f);
			break;
		}
		case SYS_EXEC:
			break;
		case SYS_WAIT:{
			tid_t child_tid = f->R.rdi;
    		f->R.rax = process_wait (child_tid);	
			break;
		}
		case SYS_CREATE:{
			char *file = f->R.rdi;
            unsigned initial_size = f->R.rsi;
            f->R.rax = sys_create (file, initial_size);
		}
			break;
		case SYS_REMOVE:
			break;
		case SYS_OPEN:{
			char *file = f->R.rdi;
			f->R.rax = sys_open(file);
			break;
		}
		case SYS_FILESIZE:{
			int fd = f->R.rdi;
			f->R.rax = sys_filesize(fd);
			break;
		}
		case SYS_READ:{
			int fd = f->R.rdi;
			void *buffer = f->R.rsi;
			unsigned size = f->R.rdx;

			f->R.rax = sys_read(fd,buffer,size);
			break;
		}
		case SYS_WRITE:{
			int fd = f->R.rdi;
			void *buffer = f->R.rsi;
			unsigned size = f->R.rdx;

			f->R.rax = sys_write(fd, buffer, size);
			break;
		}
		case SYS_SEEK:
			break;
		case SYS_TELL:
			break;
		case SYS_CLOSE:{
			sys_close(f->R.rdi);
			break;
		}
		default:
			break;
		}

	// printf ("system call!\n");
	// thread_exit ();
}

void sys_exit (int status){
    struct thread *cur = thread_current();
	
	/* child_info에 종료 상태 기록 + 부모 깨우기 */
    if (cur->child_info != NULL) {
        cur->child_info->exit_status = status;
        cur->child_info->is_exited = true;
    }
	
	printf ("%s: exit(%d)\n", thread_name(), status);

    thread_exit ();
}

void sys_halt (void){
	power_off();
}

int sys_write (int fd, const void *buffer, unsigned size){
	
	if (size == 0){
		return 0;
	}

	check_user_buffer(buffer,size);
		
	if(fd == 1){
		putbuf(buffer,size);
		return size;
	}

	if (fd <= 0 || fd >= FD_CAP) {
        return -1; 
    }

	unsigned byte_write = 0;
	struct file *cur_file = thread_current()->fd_table[fd];

	if (cur_file == NULL){
		return -1;
	}

	lock_acquire(&filesys_lock);
	byte_write = file_write(cur_file, buffer, size);
	lock_release(&filesys_lock);
	
	return (int) byte_write;
}

bool sys_create (char *file, unsigned initial_size){
	if (file == NULL ) {
        sys_exit(-1);
    }

	char *cur = file;
    
	while (true) {
        // 현재 pointer가 가리키는 '주소'가 유효한지 검사
        if (!is_user_vaddr(cur) || pml4_get_page(thread_current()->pml4, cur) == NULL) {
            sys_exit(-1);
        }

        // 문자열 끝 확인 
        if (*cur == '\0') {
            break;
        }
		// 다음 문자열 포인터 
        cur++;
    }
    //동시성 제어
    lock_acquire(&filesys_lock);
    
    // 실제 작업 수행
    bool success = filesys_create(file, initial_size);
    
    lock_release(&filesys_lock);

    return success;		

}

static void check_user_str(char *str){
	char *cur = str;

	// 포인터자체가 NULL
	if(str == NULL){
		sys_exit(-1);
	}
	// 문자열을 한 바이트씩 순회하며 모든 주소 검사
	while (true) {
        // 현재 pointer가 가리키는 '주소'가 유효한지 검사
    	if (!is_user_vaddr(cur) || pml4_get_page(thread_current()->pml4, cur) == NULL) {
            sys_exit(-1);
        }

        // 문자열 끝 확인 
        if (*cur == '\0') {
            break;
        }
		// 다음 문자열 포인터 
        cur++;
    }
}

int sys_open(char *file){

	// 유효성 검사
	check_user_str(file);

	struct thread *t = thread_current();

	//실제 파일 열기 (락으로 보호)
	lock_acquire(&filesys_lock);
    struct file *opened_file = filesys_open(file);
    lock_release(&filesys_lock);

	// 유효성 검사 
	if (opened_file == NULL){
		return -1;
	}

	// 0,1는 표준 2부터 탐색 
    for (int i = 2; i < FD_CAP; i++) {
        if (t->fd_table[i] == NULL) {
            t->fd_table[i] = opened_file;
            return i; // fd
        }
	}
	// 빈 곳 없으면 파일 닫고 실패 처리
	file_close(opened_file);
	return -1;

}

void sys_close (int fd){
	struct thread *t = thread_current();

	//유효성 검사 
	if (fd < 2 || fd>=FD_CAP){
		sys_exit(-1);
	}
 
	struct file *cur_file = t->fd_table[fd];

	// 해당 fd 파일이 null이면 조기 return
	if (cur_file == NULL) return;
	
	// 파일 닫기 (락으로 보호)
	lock_acquire(&filesys_lock);
	file_close(cur_file);
    lock_release(&filesys_lock);

	t->fd_table[fd] = NULL;

}

void check_user_buffer(void *buffer,unsigned size){
	// 마지막 바이트는 size -1 
	if (buffer == NULL || !is_user_vaddr(buffer) ||!is_user_vaddr(buffer + size -1) 
    || pml4_get_page(thread_current()->pml4, buffer) == NULL 
    || pml4_get_page(thread_current()->pml4, buffer + size - 1) == NULL) {

    sys_exit(-1);
	}
}

int sys_filesize (int fd){	
    if (fd < 2 || fd >= FD_CAP) {  
        return -1;
    }

	struct file *cur_file = thread_current()->fd_table[fd];

    if (cur_file == NULL) {
        return -1;
    }

    lock_acquire(&filesys_lock);
	off_t size = file_length(cur_file);
    lock_release(&filesys_lock);

	return (int) size;
}

int sys_read (int fd, void *buffer, unsigned size){

	if (size == 0){
		return 0;
	}

	check_user_buffer(buffer,size);
	
	unsigned byte_read = 0;
	
	if(fd == 0){
		char *buf = buffer;
		// 시작주소 부터 한글자씩 
		for(byte_read; byte_read< size; byte_read++){
			buf[byte_read] = input_getc();
		}
		return (int) byte_read;
	}

	if (fd == 1 || fd < 0 || fd >= FD_CAP) {
        return -1; 
    }

	if (fd >=2){
		struct file *cur_file = thread_current()->fd_table[fd];

		if (cur_file == NULL){
			return -1;
		}

		lock_acquire(&filesys_lock);
		byte_read = file_read(cur_file, buffer, size);
		lock_release(&filesys_lock);
	}

	return (int) byte_read;
}
