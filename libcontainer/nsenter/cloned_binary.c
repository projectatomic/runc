#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>

#include <linux/magic.h>
#include <linux/memfd.h>

/* Use our own wrapper for memfd_create. */
#if !defined(SYS_memfd_create) && defined(__NR_memfd_create)
#  define SYS_memfd_create __NR_memfd_create
#endif
#ifndef SYS_memfd_create
#  error "memfd_create(2) syscall not supported by this glibc version"
#endif
int memfd_create(const char *name, unsigned int flags)
{
	return syscall(SYS_memfd_create, name, flags);
}

/* This comes directly from <linux/fcntl.h>. */
#ifndef F_LINUX_SPECIFIC_BASE
#  define F_LINUX_SPECIFIC_BASE 1024
#endif
#ifndef F_ADD_SEALS
#  define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#  define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)
#endif
#ifndef F_SEAL_SEAL
#  define F_SEAL_SEAL   0x0001	/* prevent further seals from being set */
#  define F_SEAL_SHRINK 0x0002	/* prevent file from shrinking */
#  define F_SEAL_GROW   0x0004	/* prevent file from growing */
#  define F_SEAL_WRITE  0x0008	/* prevent writes */
#endif


#define OUR_MEMFD_COMMENT "runc_cloned:/proc/self/exe"
#define OUR_MEMFD_SEALS \
	(F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)

static void *must_realloc(void *ptr, size_t size)
{
	void *old = ptr;
	do {
		ptr = realloc(old, size);
	} while(!ptr);
	return ptr;
}

/*
 * Verify whether we are currently in a self-cloned program (namely, is
 * /proc/self/exe a memfd). F_GET_SEALS will only succeed for memfds (or rather
 * for shmem files), and we want to be sure it's actually sealed.
 */
static int is_self_cloned(void)
{
	int fd, seals;

	fd = open("/proc/self/exe", O_RDONLY|O_CLOEXEC);
	if (fd < 0)
		return -ENOTRECOVERABLE;

	seals = fcntl(fd, F_GET_SEALS);
	close(fd);
	return seals == OUR_MEMFD_SEALS;
}

/*
 * Basic wrapper around mmap(2) that gives you the file length so you can
 * safely treat it as an ordinary buffer. Only gives you read access.
 */
static char *read_file(char *path, size_t *length)
{
	int fd;
	char buf[4096], *copy = NULL;

	if (!length)
		return NULL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	*length = 0;
	for (;;) {
		int n;

		n = read(fd, buf, sizeof(buf));
		if (n < 0)
			goto error;
		if (!n)
			break;

		copy = must_realloc(copy, (*length + n) * sizeof(*copy));
		memcpy(copy + *length, buf, n);
		*length += n;
	}
	close(fd);
	return copy;

error:
	close(fd);
	free(copy);
	return NULL;
}

/*
 * A poor-man's version of "xargs -0". Basically parses a given block of
 * NUL-delimited data, within the given length and adds a pointer to each entry
 * to the array of pointers.
 */
static int parse_xargs(char *data, int data_length, char ***output)
{
	int num = 0;
	char *cur = data;

	if (!data || *output != NULL)
		return -1;

	while (cur < data + data_length) {
		num++;
		*output = must_realloc(*output, (num + 1) * sizeof(**output));
		(*output)[num - 1] = cur;
		cur += strlen(cur) + 1;
	}
	(*output)[num] = NULL;
	return num;
}

/*
 * "Parse" out argv and envp from /proc/self/cmdline and /proc/self/environ.
 * This is necessary because we are running in a context where we don't have a
 * main() that we can just get the arguments from.
 */
static int fetchve(char ***argv, char ***envp)
{
	char *cmdline = NULL, *environ = NULL;
	size_t cmdline_size, environ_size;

	cmdline = read_file("/proc/self/cmdline", &cmdline_size);
	if (!cmdline)
		goto error;
	environ = read_file("/proc/self/environ", &environ_size);
	if (!environ)
		goto error;

	if (parse_xargs(cmdline, cmdline_size, argv) <= 0)
		goto error;
	if (parse_xargs(environ, environ_size, envp) <= 0)
		goto error;

	return 0;

error:
	free(environ);
	free(cmdline);
	return -EINVAL;
}

#define SENDFILE_MAX 0x7FFFF000 /* sendfile(2) is limited to 2GB. */
static int clone_binary(void)
{
	int binfd, memfd, err;
	ssize_t sent = 0;

	memfd = memfd_create(OUR_MEMFD_COMMENT, MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (memfd < 0)
		return -ENOTRECOVERABLE;

	binfd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (binfd < 0)
		goto error;

	sent = sendfile(memfd, binfd, NULL, SENDFILE_MAX);
	close(binfd);
	if (sent < 0)
		goto error;

	err = fcntl(memfd, F_ADD_SEALS, OUR_MEMFD_SEALS);
	if (err < 0)
		goto error;

	return memfd;

error:
	close(memfd);
	return -EIO;
}

int ensure_cloned_binary(void)
{
	int execfd;
	char **argv = NULL, **envp = NULL;

	/* Check that we're not self-cloned, and if we are then bail. */
	int cloned = is_self_cloned();
	if (cloned > 0 || cloned == -ENOTRECOVERABLE)
		return cloned;

	if (fetchve(&argv, &envp) < 0)
		return -EINVAL;

	execfd = clone_binary();
	if (execfd < 0)
		return -EIO;

	fexecve(execfd, argv, envp);
	return -ENOEXEC;
}
