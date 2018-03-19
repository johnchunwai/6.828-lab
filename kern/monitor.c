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
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line
#define PERMBUF_SIZE 20	// enough for storing permission flags


// declaration
extern struct PageInfo *page_free_list;
extern struct PageInfo *spage_free_list;

static int check_addr_range(uint32_t startaddr, uint32_t endaddr);
static void parse_perm(char * output, pte_t pte);
static void do_showmappings(uintptr_t startva, uintptr_t endva);
static void do_showpdes(uintptr_t startva, uintptr_t endva);
static void do_dumpva(uintptr_t startva, uintptr_t endva);


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

struct Perm {
	const char *name;
	uint32_t val;
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "sm", "Display physical mappings and permission bits for VA range (eg. 0x3000, 0x6000)", mon_showmappings },
	{ "sd", "Display PDEs VA range (eg. 0x3000, 0x6000)", mon_showpdes },
	{ "mem", "Display general mem info", mon_meminfo },
	{ "setperm", "Set permission to a va page (eg. addperm permname val(1/0) vastart vaend)", mon_setperm},
	{ "dumpva", "Dump mem for va range", mon_dumpva},
	{ "dumppa", "Dump mem for pa range", mon_dumppa},
	{ "freepginfo", "Show some free page info", mon_freepginfo},
};

static struct Perm perms[] = {
	{ "PTE_P", 0x001 },
	{ "PTE_W", 0x002 },
	{ "PTE_U", 0x004 },
	{ "PTE_PWT", 0x008 },
	{ "PTE_PCD", 0x010 },
	{ "PTE_A", 0x020 },
	{ "PTE_D", 0x040 },
	{ "PTE_PS", 0x080 },
	{ "PTE_G", 0x100 }
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
check_addr_range(uint32_t startaddr, uint32_t endaddr)
{
	if (endaddr <= startaddr) {
		cprintf("Invalid range - endaddr must be > startaddr\n");
		return -1;
	}
	return 0;
}

int
mon_freepginfo(int argc, char **argv, struct Trapframe *tf)
{
	int spgcount = 0;
	int pgcount = 0;
	for (struct PageInfo* pp = spage_free_list; pp; pp = pp->pp_link)
		++spgcount;
	for (struct PageInfo* pp = page_free_list; pp; pp = pp->pp_link)
		++pgcount;
	assert((spgcount % PG_PER_SPG) == 0);
	spgcount = spgcount / PG_PER_SPG;
	cprintf("  free superpage count %d\n", spgcount);
	cprintf("  free page count %d\n", pgcount);

	return 0;
}

int
mon_dumppa(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3) {
		cprintf("Usage: dumppa start_pa end_pa (exclusive)\n");
		return -1;
	}

	physaddr_t startpa = (physaddr_t) strtol(argv[1], NULL, 16);
	physaddr_t endpa = (physaddr_t) strtol(argv[2], NULL, 16);

	if (0 != check_addr_range(startpa, endpa))
		return -1;

	cprintf("Dumping physical mem [0x%08x, 0x%08x)\n", startpa, endpa);
	// for (physaddr_t pa = startpa; pa < endpa; ) {
	// 	struct PageInfo *pp = pa2page(pa);
	// 	if (pp->pp_link == null) {
	// 		// page is free. dump no content
	// 		//....
	// 	}
	// 	else {
	// 		// page is not free but it might be reserved as holes
	// 		// 
	// 	}
	do_dumpva((uintptr_t) KADDR(startpa), (uintptr_t) KADDR(endpa));

	return 0;
}

int
mon_dumpva(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3) {
		cprintf("Usage: dumpva start_va end_va (exclusive)\n");
		return -1;
	}

	uintptr_t startva = (uintptr_t) strtol(argv[1], NULL, 16);
	uintptr_t endva = (uintptr_t) strtol(argv[2], NULL, 16);

	if (0 != check_addr_range(startva, endva))
		return -1;

	cprintf("Dumping virt mem [0x%08x, 0x%08x)\n", startva, endva);
	do_dumpva(startva, endva);

	return 0;
}

void
do_dumpva(uintptr_t startva, uintptr_t endva)
{
	cprintf(RED_S"--"WHITE_S": no mapping/!PTE_P, "
		CYAN_S"HH"WHITE_S": mem hole, "YELLOW_S"FF"WHITE_S": free"WHITE_S"\n");
	// dump 4 x 4 per row
	int count = 0;
	for (uintptr_t va = startva; va < endva; ) {
		// check if page exists
		uintptr_t pgend = ROUNDUP(va, PGSIZE);
		if (pgend == va)
			pgend += PGSIZE;
		pgend = MIN(pgend, endva);
		struct PageInfo *pp = page_lookup(kern_pgdir, (void *) va, NULL);
		while (va < pgend) {
			if (count % 16 == 0)
				cprintf("0x%08x    ", va);
			else if (count % 4 == 0)
				cprintf(" ");

			if (pp == NULL) {
				// no mapping or not PTE_P
				cprintf(RED_S"--");
			}
			else if (pp->pp_link != NULL) {
				// free pages
				cprintf(YELLOW_S"FF");
			}
			else if (pp->pp_ref == 0) {
				// mem hole
				cprintf(CYAN_S"HH");
			}
			else
				cprintf(WHITE_S"%02x", *(uint8_t *) va);

			if (count % 16 == 15)
				cprintf(WHITE_S"\n");
			++va;
			++count;
		}
	}
	cprintf(WHITE_S"\n");
}

int
mon_setperm(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 5) {
		cprintf("Usage: setperm permname val(1/0) start_va end_va (exclusive)\n");
		return -1;
	}

	uint32_t perm = ~0;
	for (int i = 0; i < ARRAY_SIZE(perms); i++) {
		if (strcmp(argv[1], perms[i].name) == 0)
			perm = perms[i].val;
	}
	if (perm == ~0) {
		cprintf("Unknown permname '%s'\n", argv[1]);
		return -1;
	}
	uint32_t permval = (uint32_t) strtol(argv[2], NULL, 10);
	if (permval > 1) {
		cprintf("Invalid permval %s. Acceptable vals are 0 or 1\n", argv[2]);
		return -1;
	}
	
	uintptr_t startva = (uintptr_t) strtol(argv[3], NULL, 16);
	uintptr_t endva = (uintptr_t) strtol(argv[4], NULL, 16);

	if (0 != check_addr_range(startva, endva))
		return -1;

	endva += (PGSIZE - 1);

	cprintf("Original mappings\n:");
	do_showmappings(startva, endva);

	for (uintptr_t va = startva; va < endva; va += PGSIZE) {
		pte_t * ppte = pgdir_walk(kern_pgdir, (void *) va, PGDIR_WALK_NO_CREATE);
		if (ppte != NULL) {
			if (permval == 0)
				*ppte &= ~perm;
			else
				*ppte |= perm;
		}
	}

	cprintf("Updated mappings\n:");
	do_showmappings(startva, endva);

	return 0;
}

int
mon_meminfo(int argc, char **argv, struct Trapframe *tf)
{
	mon_kerninfo(0, NULL, tf);

	size_t pages_size = npages * sizeof(struct PageInfo);
	cprintf("\nnpages=0x%08x, page info size=0x%08x, roundup=0x%08x\n", npages, pages_size, ROUNDUP(pages_size, PGSIZE));
	cprintf("bootstack @0x%08x, bootstktop @0x%08x\n", PADDR(bootstack), PADDR(bootstacktop));
	cprintf("kern_pgdir @0x%08x, pages @0x%08x\n", (uintptr_t) kern_pgdir, (uintptr_t) pages);
	cprintf("KERNBASE=0x%08x, KSTACKTOP=KERNBASE, 1st kernel stack=0x%08x, KSTACKTOP - PTSIZE=0x%08x\n",
		KERNBASE, KSTACKTOP - KSTKSIZE, KSTACKTOP - PTSIZE);
	cprintf("UPAGES=0x%08x, UPAGES_END(UPAGES+pageinfo_size)=0x%08x, UVPT(UPAGES+PTSIZE)=0x%08x\n",
		UPAGES, UPAGES + pages_size, UVPT);
	cprintf("UVPT(curr pg table)=0x%08x, ULIM=0x%08x\n", UVPT, ULIM);
	cprintf("MMIOBASE(mmap IO)=0x%08x, MMIOLIM=0x%08x\n", MMIOBASE, MMIOLIM);

	return 0;
}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3) {
		cprintf("Usage: showmappings start_va end_va (exclusive)\n");
		return -1;
	}

	uintptr_t startva = (uintptr_t) strtol(argv[1], NULL, 16);
	uintptr_t endva = (uintptr_t) strtol(argv[2], NULL, 16);

	if (0 != check_addr_range(startva, endva))
		return -1;

	endva += (PGSIZE - 1);

	do_showmappings(startva, endva);

	return 0;
}

void do_showmappings(uintptr_t startva, uintptr_t endva)
{
	cprintf("Show mappings for VA [0x%08x, 0x%08x]\n", startva, endva);
	cprintf("\n%-10s | %-10s | %s\n", "VA", "PA", "PERMS (present|R/W|U/S|WriteThru|CacheEnabled|Accessed|Dirty|PS|Global)");

	for (uintptr_t va = startva; va < endva; va += PGSIZE) {
		pte_t * ppte = pgdir_walk(kern_pgdir, (void *) va, PGDIR_WALK_NO_CREATE);
		if (ppte == NULL) {
			cprintf("0x%08x | %-10s | %s\n", va, "NA", "NA");
		}
		else {
			physaddr_t pa = PTE_ADDR(*ppte);
			char perm[PERMBUF_SIZE];
			parse_perm(perm, *ppte);
			cprintf("0x%08x | 0x%08x | %s\n", va, pa, perm);
		}
	}
}

int
mon_showpdes(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3) {
		cprintf("Usage: showpdes start_va end_va (exclusive)\n");
		return -1;
	}

	uintptr_t startva = (uintptr_t) strtol(argv[1], NULL, 16);
	uintptr_t endva = (uintptr_t) strtol(argv[2], NULL, 16);

	if (0 != check_addr_range(startva, endva))
		return -1;

	do_showpdes(startva, endva);

	return 0;
}

void do_showpdes(uintptr_t startva, uintptr_t endva)
{
	cprintf("Show PDEs for VA [0x%08x, 0x%08x]\n", startva, endva);
	cprintf("\n%-10s | %-10s | %s\n", "VA", "PA", "PERMS (present|R/W|U/S|WriteThru|CacheEnabled|Accessed|Dirty|PS|Global)");
	uintptr_t va = PDX(startva) << PDXSHIFT;
	while (va < endva) {
		pde_t *pd = kern_pgdir + PDX(va);
		if (*pd & PTE_P) {
			physaddr_t pa = PTE_ADDR(*pd);
			char perm[20];
			parse_perm(perm, *pd);
			cprintf("0x%08x | 0x%08x | %s\n", va, pa, perm);
		}
		va += (1 << PDXSHIFT);
	}
}

void
parse_perm(char * output, pte_t pte)
{
	strcpy(output, "-|R|S|-|T|-|-|4k|-");
	if (pte & PTE_P)
		output[0] = 'P';
	if (pte & PTE_W)
		output[2] = 'W';
	if (pte & PTE_U)
		output[4] = 'U';
	if (pte & PTE_PWT)
		output[6] = 'T';
	if (pte & PTE_PCD)
		output[8] = '-';
	if (pte & PTE_A)
		output[10] = 'A';
	if (pte & PTE_D)
		output[12] = 'D';
	if (pte & PTE_PS)
		output[15] = 'M';
	if (pte & PTE_G)
		output[17] = 'G';
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
