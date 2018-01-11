/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>


/*
 * This is horrible, bad yuck.  But vmmapi.h forces you to bring in tons of
 * private headers that aren't installed on the system.  It's not clear what
 * that set is and what order the -I flags need to be in.
 *
 * XXX-mg fix this
 */

enum vm_suspend_how {
	VM_SUSPEND_NONE,
	VM_SUSPEND_RESET,
	VM_SUSPEND_POWEROFF,
	VM_SUSPEND_HALT,
	VM_SUSPEND_TRIPLEFAULT,
	VM_SUSPEND_LAST
};

extern void *vm_open(const char *);
extern void vm_destroy(void *);
extern int vm_suspend(void *, enum vm_suspend_how);

int
main(int argc, char **argv) {
	char *zonename;
	void *vm;

	if (argc != 2) {
		(void) fprintf(stderr, "Error: bhyve brand halt command "
		    "expected 1 argument, got %d\n", argc - 1);
		return (1);
	}

	zonename = argv[1];

	if ((vm = vm_open(zonename)) == NULL) {
		(void) fprintf(stderr, "Notice: No bhyve vm to destroy\n");
		return (1);
	}

	if (vm_suspend(vm, VM_SUSPEND_POWEROFF) != 0 &&
	    errno != EALREADY) {
		(void) fprintf(stderr, "Notice: bhyve poweroff failed: %s\n",
		    strerror(errno));
	}

	vm_destroy(vm);

	if ((vm = vm_open(zonename)) != NULL) {
		(void) fprintf(stderr, "Error: vmm kernel state remains for "
		    " %s\n", zonename);
		return (1);
	}

	return (0);
}
