#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

#define SH_SYMTAB 2

pid_t run_target(const char* programname)
{
	pid_t pid;
	
	pid = fork();
	
    if (pid > 0) {
		return pid;
		
    } else if (pid == 0) {
		/* Allow tracing of this process */
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
			perror("ptrace");
			exit(1);
		}
		/* Replace this process's image with the given program */
		execl(programname, programname, NULL);
		
	} else {
		// fork error
		perror("fork");
        exit(1);
    }
}

void run_breakpoint_debugger(pid_t child_pid)
{
    int wait_status;
    struct user_regs_struct regs;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);

    /* Look at the word at the address we're interested in */
    unsigned long addr = 0x4000cd;
    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
    printf("DBG: Original data at 0x%x: 0x%x\n", addr, data);

    /* Write the trap instruction 'int 3' into the address */
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    wait(&wait_status);
    /* See where the child is now */
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    printf("DBG: Child stopped at RIP = 0x%x\n", regs.rip);

    /* Remove the breakpoint by restoring the previous data and set rdx = 5 */
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data);
    regs.rip -= 1;
	regs.rdx = 5;
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

    /* The child can continue running now */
    ptrace(PTRACE_CONT, child_pid, 0, 0);

    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        printf("DBG: Child exited\n");
    } else {
        printf("DBG: Unexpected signal\n");
    }
}

void run_syscall_debugger(pid_t child_pid)
{
    int wait_status;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    
	struct user_regs_struct regs;
	/* Enter next system call */
	ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
	wait(&wait_status);
	
	ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
	regs.rdx = 5;
	ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

	/* Run system call and stop on exit */
	ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
	wait(&wait_status);
	
	ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
	printf("DBG: the syscall returned: %d\n", regs.rax);
	
	/* The child can continue running now */
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        printf("DBG: Child exited\n");
    } else {
        printf("DBG: Unexpected signal\n");
    }
}

void run_regs_override_debugger(pid_t child_pid)
{
    int wait_status;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        struct user_regs_struct regs;
		
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
		regs.rdx = 5;
		ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }

        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
    }
}

void run_instruction_debugger(pid_t child_pid)
{
    int wait_status;
    int icounter = 0;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        icounter++;
        struct user_regs_struct regs;
		
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        unsigned long instr = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, NULL);

        printf("DBG: icounter = %u.  RIP = 0x%x.  instr = 0x%08x\n",
                    icounter, regs.rip, instr);

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }

        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
    }
}

void run_counter_debugger(pid_t child_pid)
{
    int wait_status;
    int icounter = 0;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        icounter++;

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }

        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
    }

    printf("DBG: the child executed %d instructions\n", icounter);
}

int isExecutable(char* file_name)
{
    int is_elf_file = 0;
    void* file;
    FILE* fd = fopen(file_name, "r");
    char* buffer = malloc(sizeof(char) * 5);
    int read_bytes = fread(buffer, 1, 4, fd);
    if(read_bytes == NULL)
        exit(1);
    if(read_bytes < 4){
        free(buffer);
        if (fclose(fd) == NULL)
            exit(1);
        return 0;
    }
    buffer[4] = '\0';
    if (strcmp(buffer + 1, "ELF") == 0){
        is_elf_file = 1;
    }
    free(buffer);
    if (is_elf_file == 1)
    {
        file = mmap(NULL, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
        Elf64_Ehdr* elf_header = (Elf64_Ehdr*)file;
        if (elf_header->e_type != ET_EXEC)
            return 0;
    }
    if (fclose(fd) == NULL)
        exit(1);
    return is_elf_file;
}

int isSymbol(char* file_name, char* symbol)
{
    FILE* fd = fopen(file_name, "r");
    if (fd == NULL)
        exit(1);
    char* file = mmap(NULL, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED)
        exit(1);
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)file;
    Elf64_Shdr* sections = (Elf64_Shdr*)(file + elf_header->e_shoff);
    Elf64_Shdr* str_section = (Elf64_Shdr*)(sections + elf_header->e_shstrndx);
    char* str_tbl = file + str_section->sh_offset;

    Elf64_Sym* symtab;
    char *strtab;
    for (int i = 0; i < header->e_shnum; i++)
        if (sections[i].sh_type == SHT_SYMTAB) {
//            todo: add !strcmp(".symtab", section_name) ||?
            symtab = (Elf64_Sym*)((char*)file + sections[i].sh_offset);
            break; }
    fclose(fd);
}

int main(int argc, char** argv)
{
    pid_t child_pid;
    if(isExecutable(argv[1]) == 0)
    {
        printf("PRF:: %s not an executable! :(\n", argv[1]);
        return 0;
    }
    if(isSymbol(argv[1], argv[0]) == 0)
    {
        printf("PRF:: %s not found!\n", argv[0]);
        return 0;
    }
    child_pid = run_target(argv[1]);
	
	// run specific "debugger"
	run_counter_debugger(child_pid);

    return 0;
}