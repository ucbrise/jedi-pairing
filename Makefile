# CXX = g++
# CXXFLAGS = -std=c++17 -I./include -Ofast
# AR = ar
# AS = as
# ASFLAGS =

ifeq ($(shell uname),Darwin)
	DISABLE_ASM=true
endif

ifeq ($(DISABLE_ASM),true)
	EXTRA_CXXFLAGS = -DDISABLE_ASM
else
# Try to autodetect the target architecture and set ARCHDIR accordingly
	ARCH = $(shell uname -m)
	ARCHDIR = src/core/arch/$(ARCH)
endif

CXX = clang++
CXXFLAGS = -std=c++17 -I./include -Ofast -fno-vectorize -fPIE $(EXTRA_CXXFLAGS)
AR = ar
AS = as
ASFLAGS =

ifneq ($(CXX_OVERRIDE),)
	CXX = $(CXX_OVERRIDE)
endif

ifneq ($(AR_OVERRIDE),)
	AR = $(AR_OVERRIDE)
endif

ifneq ($(AS_OVERRIDE),)
	AS = $(AS_OVERRIDE)
endif

# Comment out the above and uncomment the below for embedded build

# CXX = arm-none-eabi-g++
# CXXFLAGS = -std=c++17 -I./include -Os -mcpu=cortex-m0plus -mlittle-endian -mthumb -mfloat-abi=soft -mno-thumb-interwork -ffunction-sections -fdata-sections -fno-builtin -fshort-enums -fno-threadsafe-statics
# AR = arm-none-eabi-ar
# AS = arm-none-eabi-as
# ASFLAGS = -mcpu=cortex-m0plus -mlittle-endian -mthumb -mfloat-abi=soft
# ARCHDIR = src/core/arch/armv6_m

PAIRING_CPP_SOURCES = $(wildcard src/core/*.cpp) $(wildcard src/bls12_381/*.cpp) $(wildcard src/wkdibe/*.cpp) $(wildcard src/lqibe/*.cpp) $(wildcard $(ARCHDIR)/*.cpp)
PAIRING_ASM_SOURCES = $(wildcard $(ARCHDIR)/*.s)

CPP_SOURCES = $(PAIRING_CPP_SOURCES)
ASM_SOURCES = $(PAIRING_ASM_SOURCES)

BIN_OS   ?= $(shell uname)
BIN_ARCH ?= $(shell uname -m)

BINDIR = bin
PAIRING_OBJECTS = $(addprefix $(BINDIR)/,$(CPP_SOURCES:.cpp=.o)) $(addprefix $(BINDIR)/,$(ASM_SOURCES:.s=.o))

all: pairing.a ;

$(BINDIR)/builtfor-%:
	@echo "JEDI DETECTED ARCH CHANGE, CLEANING"
	@rm -rf bin
	@rm -rf pairing.a
	@mkdir -p $(BINDIR)
	@touch $@

pairing.a: $(PAIRING_OBJECTS)
	$(AR) rcs pairing.a $+

$(BINDIR)/%.o: $(BINDIR)/builtfor-$(BIN_OS)-$(BIN_ARCH) %.cpp
	mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) $(word 2,$+) -o $@

$(BINDIR)/%.o: $(BINDIR)/builtfor-$(BIN_OS)-$(BIN_ARCH) %.s
	mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $(word 2,$+) -o $@

clean:
	rm -rf bin pairing.a
