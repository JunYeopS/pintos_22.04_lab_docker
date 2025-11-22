#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
struct lock filesys_lock;

static void check_address(const void *addr);
static void check_string(const char *str);
static void handler_exit(int status);
static void handler_halt(void);
static int handler_write(int fd, const void *buffer, unsigned size);
static bool handler_create(const char *file, unsigned initial_size);
static bool handler_remove(const char *file);
static int handler_open(const char *file);
static void handler_close(int fd);
static int handler_read(int fd, void *buffer, unsigned size);
static int handler_filesize(int fd);
static tid_t handler_fork(const char *thread_name, struct intr_frame *f);
static int handler_exec(const char *cmd_line);
static void handler_seek(int fd, off_t position);
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

	lock_init(&filesys_lock); // 락 초기화
	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_num = f->R.rax;
	// f->R.rax : 시스템 콜 번호 (반환 값은 처리가 끝난 후 여기에 저장됨)
    
    // f->R.rdi : 1번째 인자 (Argument 1)
    //   자료형: int (fd, status) 또는 char* (file name) 등 상황에 따라 다름
    
    // f->R.rsi : 2번째 인자 (Argument 2)
    //   자료형: void* (buffer), unsigned (size) 등
    
    // f->R.rdx : 3번째 인자 (Argument 3)
    //   자료형: unsigned (size, count) 등

	switch (syscall_num)
	{
		case SYS_HALT:
			handler_halt();
			break;
		case SYS_EXEC:
			f->R.rax = handler_exec((const char *)f->R.rdi);
			break;
		case SYS_EXIT:
			handler_exit((int)f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = handler_fork((const char *)f->R.rdi, f);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait((tid_t)f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = handler_create((const char*)f->R.rdi, (unsigned)f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = handler_remove((const char *)f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = handler_open((const char*)f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = handler_filesize((int)f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = handler_read((int)f->R.rdi, (void*)f->R.rsi, (unsigned)f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = handler_write((int)f->R.rdi, (const void*)f->R.rsi, (unsigned)f->R.rdx);
			break;
		case SYS_SEEK:
			handler_seek((int)f->R.rdi, (off_t)f->R.rsi);
			break;
		// case SYS_TELL:
		// 	f->R.rax = handler_tell((unsigned)f->R.rdi);
		// 	break;
		case SYS_CLOSE:
			handler_close((int)f->R.rdi);
			break;
		default:
			handler_exit(-1);
			break;
	}
}

// 주소가 유효한지 유효성을 검사하는 함수
static void check_address(const void *addr){
	struct thread *cur = thread_current();

    if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(cur->pml4, addr) == NULL){
        handler_exit(-1);
    }
}

static void check_string(const char *str){
	check_address(str);

	while(*str != '\0'){
		str++;
		check_address(str);
	}
	
}

int give_fdt(struct file *file) {
    struct thread *cur = thread_current();
    struct file **fdt1 = cur->fdt_table;

    for (int fd = 2; fd < 128; fd++) {
        // 현재 검사하는 슬롯(fdt[fd])이 비어있는지(NULL) 확인
        if (fdt1[fd] == NULL) {
            fdt1[fd] = file;
            return fd;
        }
    }
    return -1;
}

// halt는 return 값이 존재하지 않는다.
void handler_halt(void){
	power_off();
}

// 현재 동작중인 유저 프로그램을 종료한다. 부모 프로세스가 현재 유저 프로그램의
// 종료를 기디리던 중이라면, 종료되면서 상태를 반환한다.
void handler_exit(int status){
	struct thread *cur = thread_current();
	cur->exit_status = status; // 자식 프로세스의 종료상태 저장
	thread_exit();
}

int handler_write(int fd, const void *buffer, unsigned size){
	if (size == 0) return 0;
	// 버퍼의 시작 주소 확인
	check_address(buffer);
	// 버퍼의 마지막 바이트 주소 확인
	check_address((const char*)buffer + size - 1);
	
	if (fd == 1){
		putbuf(buffer, size);
		return size;
	} else if (fd == 0){
		return -1;
	} else {
		// 파일 쓰기
        struct thread *cur = thread_current();
        struct file **fdt = cur->fdt_table;

        if (fd < 2 || fd >= 128 || fdt[fd] == NULL) {
            return -1;
        }

        struct file *file = fdt[fd];

        lock_acquire(&filesys_lock);
        int bytes_written = file_write(file, buffer, size);
        lock_release(&filesys_lock);

        return bytes_written;
	}
}

bool handler_create(const char *file, unsigned initial_size) {
	check_string(file);
	if (file[0] == '\0') return false;

	lock_acquire(&filesys_lock);
	bool is_create = filesys_create(file, initial_size);
	lock_release(&filesys_lock);

	return is_create;
}

int handler_open(const char* file){
	check_string(file);

	char* fn_copy = palloc_get_page(PAL_ZERO);

	strlcpy(fn_copy, file, PGSIZE);

	lock_acquire(&filesys_lock);
	struct file *cur_file = filesys_open(fn_copy);
	lock_release(&filesys_lock);

	palloc_free_page(fn_copy);

	if(cur_file == NULL){
		return -1;
	}
	
	int fd = give_fdt(cur_file);

	if (fd == -1){
		file_close(cur_file);
	}
	return fd;
}

void handler_close(int fd){ 
    struct thread *cur = thread_current();
    struct file **fdt = cur->fdt_table;

    if(fd < 2 || fd >= 128 || fdt[fd] == NULL){
        return;
    }

	lock_acquire(&filesys_lock);
    file_close(fdt[fd]);
    lock_release(&filesys_lock);

	fdt[fd] = NULL;
}

int handler_read(int fd, void* buffer, unsigned size){
	if(size == 0) return 0;
	check_address(buffer);
	check_address((char*)buffer + size -1);
	char* ptr = (char*) buffer;
	int bytes_read = 0;

	// fd 가 표준 입력이라면 파일시스템 말고
	// input_getc()함수를 사용해서 키보드의 입력을 직접 받아야 한다.
	if (fd == 0)
	{
		for (unsigned i = 0; i < size; i++)
		{
			char key = input_getc();
			*(ptr+i) = key;
			bytes_read++;
			if (key == '\0') break;
		}
		return bytes_read;
	}

	if (fd == 1) {
		return -1;
	}
	
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdt_table;

    if (fd < 2 || fd >= 128 || fdt[fd] == NULL) {
        return -1;
    }

	struct file *cur_file = fdt[fd];

	lock_acquire(&filesys_lock);
	bytes_read = file_read(cur_file, buffer, size);
	lock_release(&filesys_lock);

	return bytes_read;
}

int handler_filesize(int fd){
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdt_table;

	if (fd < 2 || fd >= 128 || fdt[fd] == NULL){
		return -1;
	}

	struct file *cur_file = fdt[fd];

	lock_acquire(&filesys_lock);
	int size = file_length(cur_file);
	lock_release(&filesys_lock);

	return size;
}

tid_t handler_fork(const char *thread_name, struct intr_frame *f){
	check_address(thread_name);
	// 부모의 값을 사용해서 fork를 해보자~
	tid_t tid = process_fork(thread_name, f);
	// sema를 통해 기다렸다가 자식의 tid를 반환한다.
	return tid;
}

int handler_exec (const char *cmd_line) {
	check_address(cmd_line);
	if (cmd_line == NULL) handler_exit(-1);
	

    struct thread *cur = thread_current();
    char* fn_copy = palloc_get_page(PAL_ZERO);
    if (fn_copy == NULL) return -1;
	
	strlcpy(fn_copy, cmd_line, PGSIZE);
	
    if (process_exec(fn_copy) == -1) {
        return -1;
    }
    
    // 성공 시 리턴 없음
    return -1;
}

void handler_seek (int fd, off_t position){
	if (fd < 2 || fd >= 128) return;
	struct thread *cur = thread_current();
	struct file *file = cur->fdt_table[fd];

	if (file == NULL) return;

	lock_acquire(&filesys_lock);
	file_seek(file, position);
	lock_release(&filesys_lock);
}

bool handler_remove (const char* file){
    check_string(file);

    if (file[0] == '\0') return false;
    
	if (filesys_remove(file)){
		return true;
	}
	return false;
}
// halt랑 exit
// enum {
// 	/* Projects 2 and later. */
// 	SYS_HALT,                   /* Clone current process. */
// 	SYS_EXEC,                     /* Halt the operating system. */
// 	SYS_EXIT,                   /* Terminate this process. */
// 	SYS_FORK,                 /* Switch current process. */
// 	SYS_WAIT,                   /* Wait for a child process to die. */
// 	SYS_CREATE,                 /* Create a file. */
// 	SYS_REMOVE,                 /* Delete a file. */
// 	SYS_OPEN,                   /* Open a file. */
// 	SYS_FILESIZE,               /* Obtain a file's size. */
// 	SYS_READ,                   /* Read from a file. */
// 	SYS_WRITE,                  /* Write to a file. */
// 	SYS_SEEK,                   /* Change position in a file. */
// 	SYS_TELL,                   /* Report current position in a file. */
// 	SYS_CLOSE,                  /* Close a file. */