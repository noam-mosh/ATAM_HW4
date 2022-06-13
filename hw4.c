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

#define UND 0

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
    char* file;
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

void isSymbol(char* file_name, char* symbol, int* symbol_found, int* is_global, int* is_defined, Elf64_Addr* symbol_address)
{
    FILE* fd = fopen(file_name, "r");
    if (fd == NULL)
        exit(1);
    char* file = mmap(NULL, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED)
        exit(1);
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)file;
    Elf64_Shdr* sections = (Elf64_Shdr*)(file + elf_header->e_shoff);

    int num_of_symbols = 0, num_of_realocs = 0;
    Elf64_Shdr section_header_str_section = sections[elf_header->e_shstrndx];
    char* section_header_str_tbl = file + section_header_str_section.sh_offset;
    char *strtab = NULL;
    Elf64_Sym* symtab = NULL;
    Elf64_Sym* dynsym = NULL;
    Elf64_Rela* plt_relocation_table = NULL;

    for (i = 0; i < elf_header->e_shnum; i++){
        if (strcmp(".symtab", section_header_str_tbl + sections[i].sh_name) == 0) {
            symtab = (Elf64_Sym*)(file + sections[i].sh_offset);
            num_of_symbols = sections[i].sh_size / sections[i].sh_entsize;
            break;
        }
        else if(strcmp(".strtab", section_header_str_tbl + sections[i].sh_name) == 0){
            strtab = (file + sections[i].sh_offset);
        }
        else if(strcmp(".dynsym", section_header_str_tbl + sections[i].sh_name) == 0){
            dynsym = (Elf64_Rela*)(file + sections[i].sh_offset);
        }
        else if(strcmp(".rela.plt", section_header_str_tbl + sections[i].sh_name) == 0){
            plt_relocation_table = (Elf64_Rela*)(file + sections[i].sh_offset);
            num_of_realocs = sections[i].sh_size / sections[i].sh_entsize;
        }
    }
    if (num_of_symbols == 0 || symtab == NULL || strtab == NULL)
        return;
    for(i = 0; i < num_of_symbols ; i++)
    {
        if(strcmp(symbol, strtab + symtab[i].st_name) == 0) {
            *symbol_found = 1;
            if(ELF64_ST_BIND(symtab[i].st_info) == GLOBAL)
                *is_global = 1;
            if(symtab[i].st_shndx != UND) {  //todo: check if value of UND is indeed 0
                *is_defined = 1;
                *symbol_address	= symtab[i].st_value;
            }
        }
    }
    if(*is_defined == 1)
    {
        if(fclose(fd) == NULL)
            exit(1);
    }

    for(i = 0; i < num_of_realocs ; i++)
    {
        Elf64_Sym dynsym_entry = dynsym + ELF64_R_SYM(plt_relocation_table[i]);
        if(strcmp(symbol, strtab + dynsym_entry.st_name) == 0) {
            &symbol_address = plt_relocation_table[i].r_offset;
        }
    }
    if(fclose(fd) == NULL)
        exit(1);
}

findSymbolPosition(char* file_name, char* symbol, Elf64_Addr* symbol_address)
{
    FILE* fd = fopen(file_name, "r");
    if (fd == NULL)
        exit(1);
    char* file = mmap(NULL, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED)
        exit(1);
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)file;
    Elf64_Shdr* sections = (Elf64_Shdr*)(file + elf_header->e_shoff);

    Elf64_Shdr section_header_str_section = sections[elf_header->e_shstrndx];
    char* section_header_str_tbl = file + section_header_str_section.sh_offset;
    char *strtab = NULL;
    Elf64_Sym* symtab = NULL;
    Elf64_Rela* text_relocation_table = NULL;
    int num_of_realocs = 0, i;

    for (i = 0; i < elf_header->e_shnum; i++){
        if (strcmp(".symtab", section_header_str_tbl + sections[i].sh_name) == 0) {
            symtab = (Elf64_Sym*)(file + sections[i].sh_offset);
            break;
        }
        else if(strcmp(".rela.text", section_header_str_tbl + sections[i].sh_name) == 0){
            text_relocation_table = (Elf64_Rela*)(file + sections[i].sh_offset);
            num_of_realocs = sections[i].sh_size / sections[i].sh_entsize;
        }
        else if(strcmp(".strtab", section_header_str_tbl + sections[i].sh_name) == 0){
            strtab = (file + sections[i].sh_offset);
        }
    }
    if (num_of_realocs == 0 || symtab == NULL || text_relocation_table == NULL || strtab == NULL)
        return;
    for(i = 0; i < num_of_realocs ; i++)
    {
        Elf64_Sym symtab_entry = symtab + ELF64_R_SYM(text_relocation_table[i]);
        if(strcmp(symbol, strtab + symtab_entry.st_name) == 0) {
            *symbol_found = 1
            if(ELF64_ST_BIND(symtab[i].st_info) == GLOBAL) {
                *is_global = 1;
            }
        }
    }
    if(fclose(fd) == NULL)
        exit(1);
    return;
}

int main(int argc, char** argv)
{
    pid_t child_pid;
    int symbol_is_found = 0, symbol_is_global = 0, symbol_is_defined = 0;
    Elf64_Addr symbol_address;
    if(isExecutable(argv[1]) == 0)
    {
        printf("PRF:: %s not an executable! :(\n", argv[1]);
        return 0;
    }
    isSymbol(argv[1], argv[0], &symbol_is_found, &symbol_is_global, &symbol_is_defined, &symbol_address);
    if(symbol_is_found == 0)
    {
        printf("PRF:: %s not found!\n", argv[0]);
        return 0;
    }
    if(symbol_is_global == 0)
    {
        printf("PRF:: <function name> is not a global symbol! :(\n", argv[0]);
        return 0;
    }
    child_pid = run_target(argv[1]);
	
	// run specific "debugger"
	run_counter_debugger(child_pid);

    return 0;
}