// SPDX-License-Identifier: GPL-2.0
/*
 * toygpu_test - exercise /dev/toygpu.
 *
 *   ./toygpu_test              functional + leak checks: safe on both builds
 *   ./toygpu_test --negative   boundary checks: on the VULN build these CORRUPT KERNEL MEMORY
 *   ./toygpu_test --race       double-fetch race on SUBMIT (VULN build + KASAN: slab-out-of-bounds)
 *
 * Expected: every line PASSes on the fixed build. On the VULN build, the FAILs (and the
 * KASAN reports in dmesg) are the bugs.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "toygpu_uapi.h"

static int fails;
static long page;

#define EXPECT(cond, ...)                                       \
	do {                                                    \
		int ok_ = !!(cond);                             \
		fails += !ok_;                                  \
		printf("  %s  ", ok_ ? "PASS" : "FAIL");        \
		printf(__VA_ARGS__);                            \
		putchar('\n');                                  \
	} while (0)

static int bo_create(int fd, uint64_t size, uint32_t *handle)
{
	struct toygpu_bo_create a = { .size = size };

	if (ioctl(fd, TOYGPU_IOCTL_BO_CREATE, &a))
		return -errno;
	*handle = a.handle;
	return 0;
}

static int bo_destroy(int fd, uint32_t handle)
{
	struct toygpu_bo_destroy d = { .handle = handle };

	return ioctl(fd, TOYGPU_IOCTL_BO_DESTROY, &d) ? -errno : 0;
}

static int submit(int fd, uint32_t handle, struct toygpu_cmdbuf *cb)
{
	struct toygpu_submit s = { .handle = handle, .cmdbuf_ptr = (uintptr_t)cb };

	return ioctl(fd, TOYGPU_IOCTL_SUBMIT, &s) ? -errno : 0;
}

static struct toygpu_cmdbuf *cmdbuf(uint32_t room, uint32_t n)
{
	struct toygpu_cmdbuf *cb = calloc(1, sizeof(*cb) + room * sizeof(cb->cmds[0]));

	if (!cb) {
		perror("calloc");
		exit(2);
	}
	cb->num_cmds = n;
	return cb;
}

static void *map_bo(int fd, uint32_t handle, size_t len)
{
	void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)handle * page);

	return p == MAP_FAILED ? NULL : p;
}

static void test_functional(int fd)
{
	struct toygpu_info info;
	const unsigned char *raw = (const unsigned char *)&info;
	size_t i, leaked = 0, nonzero = 0;
	struct toygpu_cmdbuf *cb;
	uint32_t h, *map;
	const size_t sz = 16 * page;

	printf("[functional + leak checks]\n");
	memset(&info, 0xAA, sizeof(info));
	EXPECT(ioctl(fd, TOYGPU_IOCTL_GET_INFO, &info) == 0, "GET_INFO succeeds (version %u)", info.version);
	for (i = offsetof(struct toygpu_info, num_engines) + 1; i < offsetof(struct toygpu_info, vram_size); i++)
		leaked += raw[i] != 0;
	for (i = offsetof(struct toygpu_info, max_bos) + 4; i < sizeof(info); i++)
		leaked += raw[i] != 0;
	EXPECT(leaked == 0, "GET_INFO padding is zeroed (%zu non-zero padding bytes) [BUG 1]", leaked);

	EXPECT(bo_create(fd, sz, &h) == 0, "BO_CREATE %zu bytes -> handle %u", sz, h);
	map = map_bo(fd, h, sz);
	EXPECT(map != NULL, "mmap the BO");
	if (!map)
		return;
	for (i = 0; i < sz / 4; i++)
		nonzero += map[i] != 0;
	EXPECT(nonzero == 0, "new BO memory is zeroed (%zu non-zero words) [BUG 8]", nonzero);

	cb = cmdbuf(2, 2);
	cb->cmds[0] = (struct toygpu_cmd){ .op = TOYGPU_OP_WRITE32, .offset = 0, .value = 0xdeadbeef };
	cb->cmds[1] = (struct toygpu_cmd){ .op = TOYGPU_OP_WRITE32, .offset = sz - 4, .value = 0x12345678 };
	EXPECT(submit(fd, h, cb) == 0, "SUBMIT two WRITE32 commands");
	EXPECT(map[0] == 0xdeadbeef && map[sz / 4 - 1] == 0x12345678, "GPU writes visible through the mapping");

	EXPECT(bo_destroy(fd, h) == 0, "BO_DESTROY while still mapped");
	EXPECT(map[0] == 0xdeadbeef, "mapping stays valid after destroy (VMA holds a reference) [BUG 6]");
	munmap(map, sz);
	free(cb);
}

static void test_negative(int fd)
{
	struct toygpu_cmdbuf *cb = cmdbuf(1, 1);
	struct toygpu_bo_create bad = { .size = page, .flags = 1 };
	uint32_t h, h2;
	void *m;

	printf("[negative / boundary checks]\n");
	EXPECT(ioctl(fd, _IO(TOYGPU_IOC, 0x7f)) == -1 && errno == ENOTTY, "unknown ioctl -> ENOTTY");
	EXPECT(ioctl(fd, TOYGPU_IOCTL_BO_CREATE, &bad) == -1 && errno == EINVAL, "non-zero flags -> EINVAL");
	EXPECT(bo_create(fd, 0, &h) == -EINVAL, "size 0 -> EINVAL");
	EXPECT(bo_create(fd, TOYGPU_MAX_BO_SIZE + 1ull, &h) == -EINVAL, "size > max -> EINVAL");
	if (bo_create(fd, page, &h)) {
		printf("  cannot create BO, skipping\n");
		return;
	}

	cb->cmds[0] = (struct toygpu_cmd){ .op = TOYGPU_OP_WRITE32, .value = 1 };
	EXPECT(submit(fd, 1000, cb) == -ENOENT, "SUBMIT to handle 1000 -> ENOENT [BUG 2]");

	cb->cmds[0].offset = page - 1;
	EXPECT(submit(fd, h, cb) == -EINVAL, "WRITE32 at offset size-1 -> EINVAL [BUG 5]");
	cb->cmds[0].offset = 2;
	EXPECT(submit(fd, h, cb) == -EINVAL, "unaligned WRITE32 -> EINVAL [BUG 5]");

	cb->num_cmds = 0x10000000;      /* 0x10000000 * 16 wraps a u32 to 0 */
	EXPECT(submit(fd, h, cb) == -EINVAL, "num_cmds 0x10000000 -> EINVAL [BUG 3]");
	cb->num_cmds = 1;

	m = map_bo(fd, h, 2 * page);
	EXPECT(m == NULL, "mmap 2 pages of a 1-page BO -> fails [BUG 7]");
	if (m)
		munmap(m, 2 * page);

	if (bo_create(fd, page, &h2) == 0) {
		bo_destroy(fd, h2);
		cb->cmds[0].offset = 0;
		EXPECT(submit(fd, h2, cb) == -ENOENT, "SUBMIT to a destroyed handle -> ENOENT [BUG 6]");
	}
	bo_destroy(fd, h);
	free(cb);
}

static struct toygpu_cmdbuf *race_cb;
static volatile int race_stop;

static void *flipper(void *arg)
{
	(void)arg;
	while (!race_stop) {
		__atomic_store_n(&race_cb->num_cmds, 1, __ATOMIC_RELAXED);
		__atomic_store_n(&race_cb->num_cmds, 4096, __ATOMIC_RELAXED);
	}
	return NULL;
}

static void test_race(int fd)
{
	const uint32_t room = 4096;     /* user buffer big enough that user-side reads never fault */
	unsigned long ok = 0, einval = 0, other = 0, i;
	pthread_t t;
	uint32_t h;

	printf("[double-fetch race on SUBMIT, 200000 iterations]\n");
	if (bo_create(fd, page, &h)) {
		printf("  cannot create BO, skipping\n");
		return;
	}
	race_cb = cmdbuf(room, 1);
	for (i = 0; i < room; i++)
		race_cb->cmds[i] = (struct toygpu_cmd){ .op = TOYGPU_OP_WRITE32, .offset = 0, .value = 7 };
	pthread_create(&t, NULL, flipper, NULL);
	for (i = 0; i < 200000; i++) {
		int r = submit(fd, h, race_cb);

		if (r == 0)
			ok++;
		else if (r == -EINVAL)
			einval++;
		else
			other++;
	}
	race_stop = 1;
	pthread_join(t, NULL);
	printf("  results: ok=%lu einval=%lu other=%lu\n", ok, einval, other);
	EXPECT(other == 0, "no unexpected errors (fixed build: only 0 / EINVAL)");
	printf("  On the VULN build, check dmesg for 'KASAN: slab-out-of-bounds in toygpu_submit' [BUG 4]\n");
	bo_destroy(fd, h);
	free(race_cb);
}

int main(int argc, char **argv)
{
	int fd;

	page = sysconf(_SC_PAGESIZE);
	fd = open("/dev/toygpu", O_RDWR);
	if (fd < 0) {
		perror("open /dev/toygpu (is the module loaded?)");
		return 2;
	}
	if (argc > 1 && !strcmp(argv[1], "--negative"))
		test_negative(fd);
	else if (argc > 1 && !strcmp(argv[1], "--race"))
		test_race(fd);
	else
		test_functional(fd);
	close(fd);
	printf("%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASSED", fails, fails == 1 ? "" : "s");
	return fails ? 1 : 0;
}
