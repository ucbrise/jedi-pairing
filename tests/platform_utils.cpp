#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <time.h>

extern "C" {
    void random_bytes(void* buffer, size_t len);
    uint64_t current_time_nanos(void);
}

void random_bytes(void* buffer, size_t len) {
    syscall(SYS_getrandom, buffer, len, 0);
}

uint64_t current_time_nanos(void) {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);

    uint64_t ts = ((uint64_t) 1000000000) * ((uint64_t) tp.tv_sec);
    ts += tp.tv_nsec;
    return ts;
}
