// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
asm_mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	int result;
	asm volatile (
		// string constants
		".section .data\n\t"
		"1: .asciz \"  ebp %%08x eip %%08x args %%08x %%08x %%08x %%08x %%08x\n\"\n\t"
		"2: .asciz \"Stack backtrace:\n\"\n\t"
		"3: .asciz \"          %%s:%%d: %%.*s(%%d args)+%%u\n\"\n\t"
		// code
		".section .text\n\t"
		// ebp already pushed by prologue
		"sub $0x20, %%esp\n\t"
		"pushl $2b\n\t"
		"call cprintf\n\t"

		// loop through ebp
		"mov %%ebp, %%edi\n\t"
		"begin_loop:\n\t"
		"test %%edi, %%edi\n\t"
		"jz end_loop\n\t"
		"push 0x18(%%edi)\n\t"
		"push 0x14(%%edi)\n\t"
		"push 0x10(%%edi)\n\t"
		"push 0xc(%%edi)\n\t"
		"push 0x8(%%edi)\n\t"
		"push 0x4(%%edi)\n\t"
		"push %%edi\n\t"
		"pushl $1b\n\t"
		"call cprintf\n\t"
		"add $0x20, %%esp\n\t"

		// if (0 != debuginfo_eip((uintptr_t)eip, &info)) {
		// 	panic("debuginfo_eip() returns non-zero");
		// }
		"sub $0x8, %%esp\n\t"
		"lea -0x1c(%%ebp), %%eax\n\t"
		"push %%eax\n\t"
		"push 0x4(%%edi)\n\t"
		"call debuginfo_eip\n\t"
		"add $0x10, %%esp\n\t"
		"test %%eax, %%eax\n\t"
		"jnz next_ebp\n\t"
		// cprintf("          %s:%d: %.*s(%d args)+%u\n", info.eip_file, info.eip_line,
		//     info.eip_fn_namelen, info.eip_fn_name, eip - info.eip_fn_addr);
		"sub $0x4, %%esp\n\t"
		"mov 0x4(%%edi), %%eax\n\t"
		"sub -0xc(%%ebp), %%eax\n\t"
		"push %%eax\n\t"
		"push -0x8(%%ebp)\n\t"
		"push -0x14(%%ebp)\n\t"
		"push -0x10(%%ebp)\n\t"
		"push -0x18(%%ebp)\n\t"
		"push -0x1c(%%ebp)\n\t"
		"pushl $3b\n\t"
		"call cprintf\n\t"
		"add $0x20, %%esp\n\t"

		"next_ebp:\n\t"
		"mov (%%edi), %%edi\n\t"
		"jmp begin_loop\n\t"
		"end_loop:\n\t"
		"add $0x24, %%esp\n\t"
		"mov $0x0, %0\n\t"

		: "=r" (result)	// out
		: // in
		: "%edi" // clobber (optional)
	);
	return result;
}

int
c_mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Stack backtrace:
	//   ebp f010ff78  eip f01008ae  args 00000001 f010ff8c 00000000 f0110580 00000000
	//          kern/monitor.c:143: monitor+106
	//   ebp f010ffd8  eip f0100193  args 00000000 00001aac 00000660 00000000 00000000
	//          kern/init.c:49: i386_init+59
	//   ebp f010fff8  eip f010003d  args 00000000 00000000 0000ffff 10cf9a00 0000ffff
	//          kern/entry.S:70: <unknown>+0	//   ...
	uintptr_t *p;
	uint32_t ebp, eip, arg;
	int i;
	struct Eipdebuginfo info;
	cprintf("Stack backtrace:\n");
	// get ebp
	ebp = read_ebp();
	while (ebp != 0)
	{
		// get eip (ebp + 4)
		p = (uintptr_t*)ebp;
		eip = *(++p);
		cprintf("  ebp %08x eip %08x args", ebp, eip);
		// get args 0 - 4
		for (i = 0; i < 5; ++i) {
			arg = *(++p);
			cprintf("  %08x", arg);
		}
		cprintf("\n");

		// fill in symbol info
		// struct Eipdebuginfo {
		// 	const char *eip_file;		// Source code filename for EIP
		// 	int eip_line;			// Source code linenumber for EIP

		// 	const char *eip_fn_name;	// Name of function containing EIP
		// 					//  - Note: not null terminated!
		// 	int eip_fn_namelen;		// Length of function name
		// 	uintptr_t eip_fn_addr;		// Address of start of function
		// 	int eip_fn_narg;		// Number of function arguments
		// };
		if (0 != debuginfo_eip((uintptr_t)eip, &info)) {
			panic("debuginfo_eip() returns non-zero");
		}
		cprintf("          %s:%d: %.*s(%d args)+%u\n", info.eip_file, info.eip_line,
		    info.eip_fn_namelen, info.eip_fn_name, info.eip_fn_narg, eip - info.eip_fn_addr);

		// get *ebp (next ebp)
		ebp = *(uintptr_t*)ebp;
	}
	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
