CFG_TEE_TA_LOG_LEVEL ?= 5
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)
BINARY=636f6d63-6173-7420-63727970746f2074

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

all: $O/$(BINARY).ta

$O/$(BINARY).ta: $O/$(BINARY).bin
	rm -f $@
	cat faked_armv7_uta_signed_header.bin $< > $@

clean: clean_ta_file
.PHONY: clean_ta_file
clean_ta_file:
	rm -f $(BINARY).ta
