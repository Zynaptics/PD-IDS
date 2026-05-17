/*
 * =============================================================================
 * WEEK 1 - TEST 2: MPI Hello World
 * =============================================================================
 * PURPOSE: Verify your MPI installation works. This is the classic first
 *          MPI program everyone writes.
 *
 * WHAT IS MPI?
 *   MPI = Message Passing Interface
 *   It lets you run the SAME program across MULTIPLE processes simultaneously,
 *   with each process having its own memory. Processes communicate by
 *   sending and receiving messages.
 *
 *   Think of it like this:
 *   - You hire 4 workers (processes)
 *   - Each worker runs the SAME instructions
 *   - But each worker knows their own number (rank)
 *   - They can send/receive messages to each other
 *
 * IN OUR PROJECT:
 *   - Process 0 (rank 0) = The COORDINATOR (receives packets, distributes work)
 *   - Process 1,2,3...N = The WORKERS (analyze packets for threats)
 *
 * COMPILE: mpicc -o mpi_hello mpi_hello.c
 * RUN:     mpirun -np 4 ./mpi_hello
 *          (this runs 4 processes simultaneously)
 *
 * EXPECTED OUTPUT (order may vary):
 *   Hello from process 0 of 4 - I am the COORDINATOR
 *   Hello from process 1 of 4 - I am a WORKER
 *   Hello from process 2 of 4 - I am a WORKER
 *   Hello from process 3 of 4 - I am a WORKER
 * =============================================================================
 */

#include <stdio.h>
#include <mpi.h>   /* MPI library - this is what mpicc links for us */

int main(int argc, char* argv[]) {
    int rank;   /* This process's number (0, 1, 2, ...) */
    int size;   /* Total number of processes */

    /* -----------------------------------------------------------------------
     * MPI_Init: ALWAYS the first MPI call.
     * This initializes the MPI environment and sets up communication.
     * argc and argv are passed because MPI may need command-line arguments.
     * ----------------------------------------------------------------------- */
    MPI_Init(&argc, &argv);

    /* -----------------------------------------------------------------------
     * MPI_Comm_rank: Get THIS process's rank (number/ID)
     * MPI_COMM_WORLD = the group of ALL processes running together
     * rank will be 0, 1, 2, ... size-1
     * ----------------------------------------------------------------------- */
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    /* -----------------------------------------------------------------------
     * MPI_Comm_size: Get TOTAL number of processes
     * If you ran: mpirun -np 4 ./mpi_hello
     * Then size = 4
     * ----------------------------------------------------------------------- */
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    /* Each process prints its own rank */
    if (rank == 0) {
        /* In our D-IDS project, rank 0 is always the coordinator */
        printf("Hello from process %d of %d - I am the COORDINATOR\n", rank, size);
        printf("  (In our project: I receive packets from sensors and\n");
        printf("   distribute them to worker processes for analysis)\n");
    } else {
        /* All other ranks are workers */
        printf("Hello from process %d of %d - I am a WORKER\n", rank, size);
        printf("  (In our project: I analyze packets for threats)\n");
    }

    /* -----------------------------------------------------------------------
     * MPI_Barrier: Wait for ALL processes to reach this point before continuing
     * This synchronizes all processes.
     * ----------------------------------------------------------------------- */
    MPI_Barrier(MPI_COMM_WORLD);

    /* Only the coordinator prints the summary (avoid duplicate output) */
    if (rank == 0) {
        printf("\n");
        printf("===============================================\n");
        printf("  MPI TEST PASSED!\n");
        printf("  %d processes ran simultaneously.\n", size);
        printf("  Your MPI installation is working correctly.\n");
        printf("  Ready to build the D-IDS coordinator!\n");
        printf("===============================================\n");
    }

    /* -----------------------------------------------------------------------
     * MPI_Finalize: ALWAYS the last MPI call.
     * Cleans up the MPI environment.
     * ----------------------------------------------------------------------- */
    MPI_Finalize();

    return 0;
}
