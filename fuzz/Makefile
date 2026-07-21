# Fuzz harnesses for the RX parsers in lib/mesh (handoff plan Task 1).
#
# Deliberately outside PlatformIO: these build with clang's libFuzzer against
# the portable mesh sources directly, so they cost the firmware nothing.
#
#   make            build every harness (clang + ASan/UBSan + libFuzzer)
#   make seeds      regenerate the seed corpus in corpus/ from the builders
#   make run T=sar SECS=60          run one target for a bounded time
#   make run-all SECS=60            run every target sequentially
#   make repro T=sar F=crash-xxx    replay a single crashing input
#
# Findings rule (see fuzz/README.md): every crash/UB fix gets a regression
# test in test/test_* with the offending bytes.

REPO     := ..
CC       := clang
CXX      := clang++
SECS     ?= 60
JOBS_MEM ?= 2048

TARGETS  := announce control telemetry loc sar arq kiss frame

SAN      := -fsanitize=address,undefined -fno-sanitize-recover=all
COMMON   := -g -O1 -Wall -Wextra \
            -I$(REPO)/include -I$(REPO)/lib/mesh -I$(REPO)/lib/monocypher
CXXFLAGS := -std=c++17 $(COMMON) $(SAN) -fsanitize=fuzzer-no-link
CFLAGS   := $(COMMON) $(SAN) -fsanitize=fuzzer-no-link

LIB_CPP  := $(wildcard $(REPO)/lib/mesh/*.cpp)
LIB_C    := $(wildcard $(REPO)/lib/monocypher/*.c)
OBJDIR   := build
LIB_OBJ  := $(patsubst $(REPO)/lib/mesh/%.cpp,$(OBJDIR)/mesh_%.o,$(LIB_CPP)) \
            $(patsubst $(REPO)/lib/monocypher/%.c,$(OBJDIR)/mono_%.o,$(LIB_C))

BINS     := $(TARGETS:%=$(OBJDIR)/fuzz_%)

all: $(BINS)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/mesh_%.o: $(REPO)/lib/mesh/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/mono_%.o: $(REPO)/lib/monocypher/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/fuzz_%: fuzz_%.cpp $(LIB_OBJ)
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer $< $(LIB_OBJ) -o $@

# Seed generator: plain host build, no sanitizers (it only runs trusted builders).
$(OBJDIR)/gen_seeds: gen_seeds.cpp | $(OBJDIR)
	$(CXX) -std=c++17 $(COMMON) $< $(LIB_CPP) $(LIB_C) -o $@

seeds: $(OBJDIR)/gen_seeds
	mkdir -p $(TARGETS:%=corpus/%)
	$(OBJDIR)/gen_seeds corpus

run: $(OBJDIR)/fuzz_$(T)
	mkdir -p corpus/$(T)
	$(OBJDIR)/fuzz_$(T) -max_total_time=$(SECS) -rss_limit_mb=$(JOBS_MEM) \
	    -print_final_stats=1 corpus/$(T)

run-all: all
	@for t in $(TARGETS); do \
	    echo "=== fuzz_$$t ($(SECS)s) ==="; \
	    mkdir -p corpus/$$t; \
	    $(OBJDIR)/fuzz_$$t -max_total_time=$(SECS) -rss_limit_mb=$(JOBS_MEM) \
	        corpus/$$t || exit 1; \
	done

repro: $(OBJDIR)/fuzz_$(T)
	$(OBJDIR)/fuzz_$(T) $(F)

# Re-minimise the checked-in corpus (occasionally, by hand).
minimize: all
	@for t in $(TARGETS); do \
	    mkdir -p corpus_min/$$t; \
	    $(OBJDIR)/fuzz_$$t -merge=1 corpus_min/$$t corpus/$$t || exit 1; \
	    rm -rf corpus/$$t; mv corpus_min/$$t corpus/$$t; \
	done; rmdir corpus_min

clean:
	rm -rf $(OBJDIR)

.PHONY: all seeds run run-all repro minimize clean
