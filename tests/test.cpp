#include <stdio.h>
#include <string.h>

extern "C" {
    void run_benchmarks(void);
    void run_wkdibe_tests(void);
    void run_bigint_tests(void);
    void run_tests(void);
}
int main(int argc, char** argv) {
    if (argc == 2) {
        if (strcmp(argv[1], "bigint") == 0) {
            run_bigint_tests();
            return 0;
        }
        if (strcmp(argv[1], "bench") == 0) {
            run_benchmarks();
            return 0;
        }
        if (strcmp(argv[1], "wkdibe") == 0) {
            run_wkdibe_tests();
            return 0;
        }
        printf("Invalid command\n");
        return 1;
    }
    run_tests();
    return 0;
}
