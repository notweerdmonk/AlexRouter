SOURCES := test_hermes.cc test.cc
OBJECTS := $(SOURCES:.cc=.o)
TARGETS := $(OBJECTS:.o=)

all: $(TARGETS)

$(TARGETS) : $(OBJECTS)

%.o: %.cc hermes.hpp
	g++ -ggdb3 -I. -c -o $@ $<

%: %.o
	g++ -ggdb3 -o $@ $<

clean:
	rm -f $(OBJECTS) $(TARGETS)
