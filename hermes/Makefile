SOURCES := test_hermes.cc
OBJECTS := $(SOURCES:.cc=.o)
TARGETS := $(OBJECTS:.o=)

CXX := g++

SUPPORTED_CXX_VERSIONS := c++11 c++14 c++17 c++20 c++23

ifeq ($(CXX_VERSION),)
CXX_VERSION := c++23
else
ifeq ($(findstring $(CXX_VERSION), $(SUPPORTED_CXX_VERSIONS)),)
CXX_VERSION := c++23
endif
endif

INCLUDE_DIRS := $(CURDIR) $(realpath ../testftw)

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(dir))

INCLUDE_HEADERS := $(foreach dir,$(INCLUDE_DIRS),$(wildcard $(dir)/*.hpp))
INCLUDE_HEADERS += $(foreach dir,$(INCLUDE_DIRS),$(wildcard $(dir)/*.h))

all: $(TARGETS)

test: $(TARGETS)
	./test_hermes

buildcompat:
	for version in $(SUPPORTED_CXX_VERSIONS); do \
		make clean; \
		CXX_VERSION=$${version} make; \
	done

compat:
	for version in $(SUPPORTED_CXX_VERSIONS); do \
		make clean; \
		CXX_VERSION=$${version} make; \
		make test; \
	done

$(TARGETS) : $(OBJECTS)

%.o: %.cc $(INCLUDE_HEADERS)
	$(CXX) -std=$(CXX_VERSION) -ggdb3 $(INCLUDE_FLAGS) -c -o $@ $<

%: %.o
	$(CXX) -std=$(CXX_VERSION) -ggdb3 -o $@ $<

clean:
	rm -f $(OBJECTS) $(TARGETS)
