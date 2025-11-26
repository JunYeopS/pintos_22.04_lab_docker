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
#include "threads/palloc.h"
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
int sys_exec (const char *cmd_line);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
bool sys_remove (const char *file);
int sys_dup2(int oldfd, int newfd);

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
			const char *cmd_line = f->R.rdi;
			sys_exec(cmd_line);
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
		case SYS_REMOVE:{
			const char *file = f->R.rdi;
			f->R.rax = sys_remove(file);
			break;
		}
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
			sys_seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:{
			int fd = f->R.rdi;
			f->R.rax = sys_tell(fd);
		}
			break;
		case SYS_CLOSE:{
			sys_close(f->R.rdi);
			break;
		}
		case SYS_DUP2:{
			int oldfd = f->R.rdi;
            int newfd = f->R.rsi;
            f->R.rax = sys_dup2(oldfd, newfd);
		}
		default:
			break;
		}
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

	if (fd < 0 || fd >= FD_CAP) {
		return -1; 
	}

	check_user_buffer(buffer, size);

	struct file *f = thread_current()->fd_table[fd];

	/* stdout 처리 (센티널 체크) */
	if (fd >= 0 && fd < FD_CAP) {
		if (f == STDOUT_SENTINEL) {
			putbuf(buffer, size);
			return size;
		}
	}


	/* stdin이나 NULL 체크 */
	if (f== NULL || f == STDIN_SENTINEL) {
		return -1;
	}

	lock_acquire(&filesys_lock);
	unsigned byte_write = file_write(f, buffer, size);
	lock_release(&filesys_lock);
	
	return (int) byte_write;
}

bool sys_create (char *file, unsigned initial_size){
	if (file == NULL) {
        sys_exit(-1);
    }

	check_user_str(file);

	lock_acquire(&filesys_lock);
	bool success = filesys_create(file, initial_size);
	lock_release(&filesys_lock);

	return success;		
}

static void check_user_str(char *str){
	char *cur = str;

	if (str == NULL){
		sys_exit(-1);
	}

	while (true) {
		if (!is_user_vaddr(cur) || pml4_get_page(thread_current()->pml4, cur) == NULL) {
			sys_exit(-1);
		}

		if (*cur == '\0') {
			break;
		}
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

    for (int i = 0; i < FD_CAP; i++) {
        if (t->fd_table[i] == NULL) {
            t->fd_table[i] = opened_file; 
            return i; // fd
        }
	}
	
	// 빈 곳 없으면 파일 닫고 실패 처리
	lock_acquire(&filesys_lock);
	file_close(opened_file);
	lock_release(&filesys_lock);
	
	return -1;
}

void sys_close (int fd){
	struct thread *t = thread_current();

	//유효성 검사 
	if (fd < 0 || fd>=FD_CAP){
		sys_exit(-1);
		return;
	}
 
	struct file *cur_file = t->fd_table[fd];

	/* NULL 또는 stdin/stdout 센티널은 닫지 않음 */
	if (cur_file == NULL || cur_file == STDIN_SENTINEL || cur_file == STDOUT_SENTINEL) {
		return;
	}
	
	/* 참조 카운트 감소 */
	cur_file->ref_cnt--;

	/* 참조 카운트가 0이면 실제로 파일 닫기 */
	if (cur_file->ref_cnt == 0) {
		lock_acquire(&filesys_lock);
		file_close(cur_file);
		lock_release(&filesys_lock);
	}

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
    if (fd < 0 || fd >= FD_CAP) {  
        return -1;
    }

	struct file *cur_file = thread_current()->fd_table[fd];

	/* NULL 또는 stdin/stdout은 filesize 없음 */
	if (cur_file == NULL || cur_file == STDIN_SENTINEL || cur_file == STDOUT_SENTINEL) {
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

	check_user_buffer(buffer, size);

	if (fd < 0 || fd >= FD_CAP) {
		return -1; 
	}

	/* stdin 처리 (센티널 체크) */
	if (fd >= 0 && fd < FD_CAP) {
		struct file *f = thread_current()->fd_table[fd];
		if (f == STDIN_SENTINEL) {
			char *buf = buffer;
			for (unsigned i = 0; i < size; i++) {
				buf[i] = input_getc();
			}
			return (int) size;
		}
	}

	struct file *cur_file = thread_current()->fd_table[fd];

	/* stdout이나 NULL 체크 */
	if (cur_file == NULL || cur_file == STDOUT_SENTINEL) {
		return -1;
	}

	lock_acquire(&filesys_lock);
	unsigned byte_read = file_read(cur_file, buffer, size);
	lock_release(&filesys_lock);

	return (int) byte_read;
}

int sys_exec(const char *cmd_line){
	
	check_user_str(cmd_line);

	char *cmd_copy = palloc_get_page(PAL_ZERO);
	if (cmd_copy == NULL){
		return -1;
	}
	strlcpy(cmd_copy,cmd_line, PGSIZE);

	int succ = process_exec(cmd_copy);

    if (succ == -1) {
        sys_exit (-1);      
    }          
}

void sys_seek (int fd, unsigned position){
	if (fd < 0 || fd >= FD_CAP) {
		return;
	}

	struct file *cur_file = thread_current()->fd_table[fd];
	
	/* NULL 또는 stdin/stdout은 seek 불가 */
	if (cur_file == NULL || cur_file == STDIN_SENTINEL || cur_file == STDOUT_SENTINEL) {
		return;
	} 

	lock_acquire(&filesys_lock);
	file_seek(cur_file, position);
	lock_release(&filesys_lock);
}

bool sys_remove (const char *file){
	check_user_str(file);

	lock_acquire(&filesys_lock);
	bool success = filesys_remove(file);
	lock_release(&filesys_lock);

	return success;
}

unsigned sys_tell(int fd){
	if (fd < 0 || fd >= FD_CAP){
		return 0;
	}

	struct file *cur_file = thread_current()->fd_table[fd];
	
	/* NULL 또는 stdin/stdout은 tell 불가 */
	if (cur_file == NULL || cur_file == STDIN_SENTINEL || cur_file == STDOUT_SENTINEL) {
		return 0; 
	}
		
	lock_acquire(&filesys_lock);
    off_t offset = file_tell(cur_file);
    lock_release(&filesys_lock);
	return (unsigned) offset;
}

int sys_dup2(int oldfd, int newfd){

	if (oldfd < 0 || oldfd >= FD_CAP || newfd < 0 || newfd >= FD_CAP) {
		return -1;
	}

	struct thread *cur = thread_current();
	struct file *old_f = cur->fd_table[oldfd];

	if (old_f == NULL) {
		return -1;
	}

	/* fd가 같으면 바로 반환 */
	if (oldfd == newfd) {
		return newfd;
	}
	
	struct file *new_f = cur->fd_table[newfd];
	
	/* new_f가 열려 있을때 처리*/
	sys_close(newfd);

	/* newfd -> oldfd를 참조 */
	cur->fd_table[newfd] = old_f;
	
	/* stdin/stdout 아닌 경우에만 참조 카운트 증가 */
	if (old_f != STDIN_SENTINEL && old_f != STDOUT_SENTINEL) {
		old_f->ref_cnt++;
	}

	return newfd;
}
