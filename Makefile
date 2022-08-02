# CXX = g++
# CXXFLAGS = -std=c++17 -I./include -Ofast
# AR = ar
# AS = as
# ASFLAGS =

CXX = clang++
CXXFLAGS = -std=c++17 -I./include -Ofast -fno-vectorize
AR = ar
AS = as
ASFLAGS =

CXXFLAGS += -fPIE

# Try to autodetect the target architecture and set ARCHDIR accordingly
ARCH = $(shell uname -m)
ARCHDIR = src/core/arch/$(ARCH)

# Comment out the above and uncomment the below for embedded build

# CXX = arm-none-eabi-g++
# CXXFLAGS = -std=c++17 -I./include -Os -mcpu=cortex-m0plus -mlittle-endian -mthumb -mfloat-abi=soft -mno-thumb-interwork -ffunction-sections -fdata-sections -fno-builtin -fshort-enums -fno-threadsafe-statics
# AR = arm-none-eabi-ar
# AS = arm-none-eabi-as
# ASFLAGS = -mcpu=cortex-m0plus -mlittle-endian -mthumb -mfloat-abi=soft
# ARCHDIR = src/core/arch/armv6_m

ifeq ($(ARCH),arm64)
CXXFLAGS += -DDISABLE_ASM
endif

PAIRING_CPP_SOURCES = $(wildcard src/core/*.cpp) $(wildcard src/bls12_381/*.cpp) $(wildcard src/wkdibe/*.cpp) $(wildcard src/lqibe/*.cpp) $(wildcard $(ARCHDIR)/*.cpp)
PAIRING_ASM_SOURCES = $(wildcard $(ARCHDIR)/*.s)

CPP_SOURCES = $(PAIRING_CPP_SOURCES)
ASM_SOURCES = $(PAIRING_ASM_SOURCES)

BINDIR = bin
PAIRING_OBJECTS = $(addprefix $(BINDIR)/,$(CPP_SOURCES:.cpp=.o)) $(addprefix $(BINDIR)/,$(ASM_SOURCES:.s=.o))

all: pairing.a

pairing.a: $(PAIRING_OBJECTS)
	$(AR) rcs pairing.a $+

$(BINDIR)/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(BINDIR)/%.o: %.s
	mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -rf bin pairing.a
