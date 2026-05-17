# =============================================================================
# MAKEFILE - Build system for D-IDS project
# =============================================================================
#
# WHAT IS A MAKEFILE?
#   Instead of typing long compile commands every time, you just type "make".
#   Make reads this file and runs the right commands automatically.
#
# HOW TO USE:
#   make all          - Build everything
#   make week1        - Build and run Week 1 tests
#   make week2        - Build packet capture sensor (Week 2)
#   make week3        - Build signature detection tests (Week 3)
#   make week4        - Build MPI coordinator (Week 4)
#   make run-week4    - Run the full parallel system
#   make speedup      - Run speedup experiment (Week 4)
#   make clean        - Delete all compiled files
#   make help         - Show this help
#
# SYNTAX NOTES:
#   $(CC)      = the C compiler (gcc)
#   $(MPICC)   = the MPI C compiler wrapper
#   $(CFLAGS)  = compiler flags (optimization, warnings)
#   $@         = the target file being built
#   $<         = the first dependency
#   $^         = all dependencies
# =============================================================================

# --- Compiler Settings ---
CC     = gcc
MPICC  = mpicc
CFLAGS = -O2 -Wall -Wextra -g

# --- Libraries ---
LIBS_PCAP = -lpcap
LIBS_MATH = -lm
LIBS_ALL  = $(LIBS_PCAP) $(LIBS_MATH)

# --- Directories ---
BUILD_DIR   = build
SENSOR_DIR  = sensor
CENTRAL_DIR = central
TEST_DIR    = tests
DATA_DIR    = data

# --- Output colors (for pretty output) ---
RED    = \033[0;31m
GREEN  = \033[0;32m
YELLOW = \033[0;33m
BLUE   = \033[0;34m
RESET  = \033[0m

# =============================================================================
# DEFAULT TARGET: runs when you just type "make"
# =============================================================================
.PHONY: all
all: setup week1 week2 week3 week4
	@echo ""
	@printf "$(GREEN)╔══════════════════════════════════════╗$(RESET)\n"
	@printf "$(GREEN)║  ALL WEEKS BUILT SUCCESSFULLY!       ║$(RESET)\n"
	@printf "$(GREEN)╚══════════════════════════════════════╝$(RESET)\n"

# =============================================================================
# SETUP: Create directories
# =============================================================================
.PHONY: setup
setup:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(DATA_DIR)/logs
	@mkdir -p $(DATA_DIR)/test_pcaps
	@mkdir -p $(DATA_DIR)/attack_signatures
	@mkdir -p $(DATA_DIR)/results

# =============================================================================
# WEEK 1: Environment tests
# =============================================================================
.PHONY: week1
week1: setup $(BUILD_DIR)/hello_world $(BUILD_DIR)/mpi_hello
	@printf "$(GREEN)[Week 1] Environment tests built.$(RESET)\n"
	@printf "$(YELLOW)  Run: ./$(BUILD_DIR)/hello_world$(RESET)\n"
	@printf "$(YELLOW)  Run: mpirun -np 4 ./$(BUILD_DIR)/mpi_hello$(RESET)\n"

# Compile hello_world.c
# -o $(BUILD_DIR)/hello_world   : output file name
# $(TEST_DIR)/hello_world.c     : input file
$(BUILD_DIR)/hello_world: $(TEST_DIR)/hello_world.c
	@printf "$(BLUE)  Compiling hello_world...$(RESET)\n"
	$(CC) $(CFLAGS) -o $@ $<
	@printf "$(GREEN)  ✅ hello_world compiled$(RESET)\n"

# Compile mpi_hello.c using mpicc
$(BUILD_DIR)/mpi_hello: $(TEST_DIR)/mpi_hello.c
	@printf "$(BLUE)  Compiling mpi_hello (MPI)...$(RESET)\n"
	$(MPICC) $(CFLAGS) -o $@ $<
	@printf "$(GREEN)  ✅ mpi_hello compiled$(RESET)\n"

# =============================================================================
# WEEK 2: Packet capture sensor
# =============================================================================
.PHONY: week2
week2: setup $(BUILD_DIR)/packet_capture
	@printf "$(GREEN)[Week 2] Packet capture sensor built.$(RESET)\n"
	@printf "$(YELLOW)  Run: sudo ./$(BUILD_DIR)/packet_capture -i lo -n 20$(RESET)\n"
	@printf "$(YELLOW)  (needs sudo for raw packet access)$(RESET)\n"

$(BUILD_DIR)/packet_capture: $(SENSOR_DIR)/packet_capture.c
	@printf "$(BLUE)  Compiling packet_capture...$(RESET)\n"
	$(CC) $(CFLAGS) -o $@ $< $(LIBS_PCAP) $(LIBS_MATH)
	@printf "$(GREEN)  ✅ packet_capture compiled$(RESET)\n"

# =============================================================================
# WEEK 3: Signature detection engine
# =============================================================================
.PHONY: week3
week3: setup $(BUILD_DIR)/signature_detection
	@printf "$(GREEN)[Week 3] Signature detection built.$(RESET)\n"
	@printf "$(YELLOW)  Run: ./$(BUILD_DIR)/signature_detection$(RESET)\n"

$(BUILD_DIR)/signature_detection: $(CENTRAL_DIR)/signature_detection.c
	@printf "$(BLUE)  Compiling signature_detection...$(RESET)\n"
	$(CC) $(CFLAGS) -o $@ $< $(LIBS_MATH)
	@printf "$(GREEN)  ✅ signature_detection compiled$(RESET)\n"

# =============================================================================
# WEEK 4: MPI Coordinator
# =============================================================================
.PHONY: week4
week4: setup $(BUILD_DIR)/coordinator
	@printf "$(GREEN)[Week 4] MPI coordinator built.$(RESET)\n"
	@printf "$(YELLOW)  Run: mpirun -np 5 ./$(BUILD_DIR)/coordinator -n 200$(RESET)\n"

$(BUILD_DIR)/coordinator: $(CENTRAL_DIR)/coordinator_mpi.c
	@printf "$(BLUE)  Compiling coordinator (MPI)...$(RESET)\n"
	$(MPICC) $(CFLAGS) -o $@ $< $(LIBS_MATH)
	@printf "$(GREEN)  ✅ coordinator compiled$(RESET)\n"

# =============================================================================
# RUN TARGETS - actually execute the programs
# =============================================================================

# Week 1: Run hello world
.PHONY: run-week1
run-week1: week1
	@printf "\n$(BLUE)=== Running Week 1: Hello World ===$(RESET)\n\n"
	./$(BUILD_DIR)/hello_world
	@printf "\n$(BLUE)=== Running Week 1: MPI Hello ===$(RESET)\n\n"
	mpirun -np 4 ./$(BUILD_DIR)/mpi_hello

# Week 3: Run detection tests
.PHONY: run-week3
run-week3: week3
	@printf "\n$(BLUE)=== Running Week 3: Detection Tests ===$(RESET)\n\n"
	./$(BUILD_DIR)/signature_detection

# Week 4: Run full parallel system
.PHONY: run-week4
run-week4: week4
	@printf "\n$(BLUE)=== Running Week 4: Parallel IDS (4 workers) ===$(RESET)\n\n"
	mpirun -np 5 ./$(BUILD_DIR)/coordinator -n 500

# =============================================================================
# SPEEDUP EXPERIMENT
#
# This runs the coordinator with different numbers of workers and records
# how fast it is. Use the output to create your speedup graph!
#
# Speedup = Time_with_1_worker / Time_with_N_workers
# =============================================================================
.PHONY: speedup
speedup: week4
	@printf "\n$(BLUE)==================================$(RESET)\n"
	@printf "$(BLUE)  SPEEDUP EXPERIMENT$(RESET)\n"
	@printf "$(BLUE)==================================$(RESET)\n\n"
	@printf "$(YELLOW)Analyzing 1000 packets with different numbers of workers...$(RESET)\n\n"
	@printf "Workers=1:\n"
	mpirun -np 2 ./$(BUILD_DIR)/coordinator -n 1000
	@printf "\nWorkers=2:\n"
	mpirun -np 3 ./$(BUILD_DIR)/coordinator -n 1000
	@printf "\nWorkers=4:\n"
	mpirun -np 5 ./$(BUILD_DIR)/coordinator -n 1000
	@printf "\nWorkers=8:\n"
	mpirun -np 9 ./$(BUILD_DIR)/coordinator -n 1000
	@printf "\n$(GREEN)Speedup experiment complete!$(RESET)\n"
	@printf "$(YELLOW)Copy the timing numbers above into your report.$(RESET)\n"
	@printf "$(YELLOW)Speedup = 1-worker-time / N-worker-time$(RESET)\n"

# =============================================================================
# CLEAN: Remove all compiled files
# =============================================================================
.PHONY: clean
clean:
	@printf "$(RED)Removing compiled files...$(RESET)\n"
	rm -rf $(BUILD_DIR)
	@printf "$(GREEN)Clean done.$(RESET)\n"

# =============================================================================
# HELP
# =============================================================================
.PHONY: help
help:
	@printf "\n$(BLUE)D-IDS PROJECT - MAKE COMMANDS$(RESET)\n"
	@printf "================================\n"
	@printf "$(GREEN)make all$(RESET)          - Build all weeks\n"
	@printf "$(GREEN)make week1$(RESET)        - Build Week 1 (env tests)\n"
	@printf "$(GREEN)make week2$(RESET)        - Build Week 2 (packet capture)\n"
	@printf "$(GREEN)make week3$(RESET)        - Build Week 3 (signature detection)\n"
	@printf "$(GREEN)make week4$(RESET)        - Build Week 4 (MPI coordinator)\n"
	@printf "$(GREEN)make run-week1$(RESET)    - Run Week 1 tests\n"
	@printf "$(GREEN)make run-week3$(RESET)    - Run detection tests\n"
	@printf "$(GREEN)make run-week4$(RESET)    - Run full parallel system\n"
	@printf "$(GREEN)make speedup$(RESET)      - Run speedup experiment\n"
	@printf "$(GREEN)make clean$(RESET)        - Remove compiled files\n"
	@printf "\n"
