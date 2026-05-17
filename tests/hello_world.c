/*
 * =============================================================================
 * WEEK 1 - TEST 1: Hello World in C
 * =============================================================================
 * PURPOSE: Verify your C compiler (GCC) works correctly.
 *
 * COMPILE: gcc -o hello_world hello_world.c
 * RUN:     ./hello_world
 *
 * EXPECTED OUTPUT:
 *   ================================================
 *   D-IDS PROJECT - ENVIRONMENT TEST
 *   ================================================
 *   [OK] C compiler is working!
 *   [OK] Printf is working!
 *   [OK] Variables work: x=10, y=20, sum=30
 *   [OK] Loops work: 0 1 2 3 4
 *   [OK] Functions work: square(5) = 25
 *   ================================================
 *   All basic C tests PASSED! Ready for Week 2.
 *   ================================================
 * =============================================================================
 */

#include <stdio.h>    /* printf, scanf */
#include <stdlib.h>   /* malloc, free */
#include <string.h>   /* strcpy, strlen */
#include <time.h>     /* time() */

/* ==========================================================================
 * A simple function to test that function calls work
 * ========================================================================== */
int square(int n) {
    return n * n;
}

/* ==========================================================================
 * Main function - entry point of every C program
 * ========================================================================== */
int main() {
    printf("================================================\n");
    printf("  D-IDS PROJECT - ENVIRONMENT TEST\n");
    printf("================================================\n");

    /* Test 1: Basic printf */
    printf("[OK] C compiler is working!\n");
    printf("[OK] Printf is working!\n");

    /* Test 2: Variables */
    int x = 10, y = 20;
    int sum = x + y;
    printf("[OK] Variables work: x=%d, y=%d, sum=%d\n", x, y, sum);

    /* Test 3: Loops */
    printf("[OK] Loops work: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
    }
    printf("\n");

    /* Test 4: Functions */
    printf("[OK] Functions work: square(5) = %d\n", square(5));

    /* Test 5: Strings */
    char project_name[50];
    strcpy(project_name, "Distributed IDS");
    printf("[OK] Strings work: project = %s\n", project_name);

    /* Test 6: Memory allocation */
    int* array = (int*)malloc(5 * sizeof(int));
    if (array == NULL) {
        printf("[FAIL] Memory allocation failed!\n");
        return 1;
    }
    for (int i = 0; i < 5; i++) array[i] = i * 10;
    printf("[OK] Memory allocation works: array[3] = %d\n", array[3]);
    free(array);  /* Always free memory you allocate! */

    /* Test 7: Time functions (we use these in packet capture) */
    time_t now = time(NULL);
    printf("[OK] Time functions work: current time = %ld\n", (long)now);

    printf("================================================\n");
    printf("  All basic C tests PASSED! Ready for Week 2.\n");
    printf("================================================\n");

    return 0;  /* 0 means success in C */
}
