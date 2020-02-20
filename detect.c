/*
 * Author: manizzle
 * Heavily based off of https://github.com/elfmaster/libelfmaster/blob/master/examples/pltgot.c
 * Detects .plt.got infections in dynamically linked executable files
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <search.h>
#include <sys/time.h>
#include <libelfmaster.h>

int main(int argc, char **argv)
{
	elfobj_t obj;
	elf_error_t error;
	elf_pltgot_iterator_t pltgot_iter;
	struct elf_pltgot_entry pltgot;
	struct elf_section plt_section;
	int dynamic;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj, ELF_LOAD_F_FORENSICS, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	// This heuristic only works for Dynamically Linked executables
	// Statically linked executables (that do not have -no-stdlib) will
	// still have .got.plt entries that point directly the the embedded code
	if (obj.type != ET_EXEC)
		return -1;
    if (!obj.dynseg.exists)
    	return -1;

	elf_section_by_name(&obj, ".plt", &plt_section);
	elf_pltgot_iterator_init(&obj, &pltgot_iter);
	while (elf_pltgot_iterator_next(&pltgot_iter, &pltgot) == ELF_ITER_OK) {
		// Rules
		// 1) If the value is 0, ignore
		// 2) If the value points to the top of the Dynamic Segment, ignore (.got.plt has a pointer to it)
		// 3) If the value is not within the .plt section, then you have an infection!
		if (pltgot.value && pltgot.value != obj.dynamic_addr && \
			(!((pltgot.value >= plt_section.address) && (pltgot.value < (plt_section.address + plt_section.size))))) {
			printf("GOT object is infected (%#lx): %#08lx %s\n", pltgot.offset,
		    	pltgot.value, elf_pltgot_flag_string(pltgot.flags));
		}
	}
	return 0;
}

