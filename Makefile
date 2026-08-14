obj-m := kerncall.o

kerncall-y := src/main.o lib/sc.o lib/sc_slide.o \
	deps/KallRecon/lib/core.o deps/KallRecon/lib/slide.o deps/KallRecon/lib/anchor.o

ccflags-y += -std=gnu11
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-strict-prototypes
ccflags-y += -I$(src)/lib
ccflags-y += -I$(src)/deps/KallRecon/lib

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ODIR := $(MDIR)/out/$(VER)

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))
$(info -- ODIR: $(ODIR))

all:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) modules
clean:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) clean

ifneq ($(KERNSC_MINIMAL),1)
ccflags-y += -DCONFIG_KERNSC_DISCOVER -DCONFIG_KERNSC_PATCH -DCONFIG_KERNSC_TP
endif

$(obj)/%.o: $(src)/%.c $(recordmcount_source) FORCE
	$(call if_changed_rule,cc_o_c)
	$(call cmd,force_checksrc)

$(obj)/%.o: $(src)/%.S FORCE
	$(call if_changed_rule,as_o_S)
