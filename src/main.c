/*
 * Bitcoin Echo — Main Entry Point
 *
 * Build once. Build right. Stop.
 */

#include <stdio.h>

#define ECHO_VERSION_MAJOR 0
#define ECHO_VERSION_MINOR 0
#define ECHO_VERSION_PATCH 1

int main(int argc, char *argv[])
{
    (void)argc;  /* Unused for now */
    (void)argv;  /* Unused for now */

    printf("Bitcoin Echo v%d.%d.%d\n",
           ECHO_VERSION_MAJOR,
           ECHO_VERSION_MINOR,
           ECHO_VERSION_PATCH);
    printf("A complete Bitcoin protocol implementation in pure C.\n");

    return 0;
}
