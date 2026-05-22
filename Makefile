SHELL := /bin/bash
CC := g++

SUPPORTED_CXX_VERSIONS := c++11 c++14 c++17 c++20 c++23


ifeq ($(CXX_VERSION),)
CXX_VERSION := c++23
else
ifeq ($(findstring $(CXX_VERSION), $(SUPPORTED_CXX_VERSIONS)),)
CXX_VERSION := c++23
endif
endif

ifneq ($(DEBUG),)
CFLAGS += -ggdb3
endif

ifeq ($(OPTIM),)

ifneq ($(DEBUG),)
OPTIM :=
else
OPTIM := -O3
endif

endif

CFLAGS += $(OPTIM) -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wstrict-aliasing=2

ifeq ($(INCLUDE_DIR),)
INCLUDE_DIR := .
endif

HEADER_FILES := HttpRouter.hpp
HEADER_FILES := $(foreach header, $(HEADER_FILES), $(INCLUDE_DIR)/$(header))

DEP_MODULES := hermes
DEP_HEADER_FILES += $(foreach header, $(wildcard $(DEP_MODULES)/*.h), $(header))
DEP_HEADER_FILES += $(foreach header, $(wildcard $(DEP_MODULES)/*.hpp), $(header))
DEP_HEADER_FILES := $(foreach header, $(DEP_HEADER_FILES), $(header))

INCLUDE_DIR += $(DEP_MODULES)

INCLUDE_FLAGS := $(foreach include_dir, $(INCLUDE_DIR), -I$(include_dir))

LIBS :=
LD_FLAGS := $(foreach lib, $(LIBS), -l$(lib))

SRCS := tests.cpp

OBJECTS := $(SRCS:.cpp=.o)

TARGETS := $(SRCS:.cpp=)

all: $(TARGETS)

$(OBJECTS): $(HEADER_FILES) $(DEP_HEADER_FILES)

$(TARGETS): $(OBJECTS)

./%: ./%.o
	$(CC) $(INCLUDE_FLAGS) -o $@ $< $(LD_FLAGS)

./%.o: ./%.cpp $(HEADER_FILES) $(DEP_HEADER_FILES)
	$(CC) -std=$(CXX_VERSION) $(CFLAGS) $(INCLUDE_FLAGS) -o $@ -c $<

test: $(TARGETS)
	./tests --test

check-all-versions:
	for version in $(SUPPORTED_CXX_VERSIONS); do \
		make clean; \
		CXX_VERSION=$${version} make; \
	done

test-all-versions:
	for version in $(SUPPORTED_CXX_VERSIONS); do \
		make clean; \
		CXX_VERSION=$${version} make; \
		make test; \
	done

clean:
	rm -f $(OBJECTS) $(TARGETS) 

.PHONY: all clean test
