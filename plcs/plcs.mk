# Relative to plc subdirectory
OPENPLC_DIR=../../OpenPLC_v2

# Relative to OPENPLC_DIR
PLC_DIR=../plcs

BUILD_FILES=POUS.c POUS.h LOCATED_VARIABLES.h VARIABLES.csv Config0.c Config0.h Res0.c

%: %.st
	cd $(OPENPLC_DIR) && \
	./iec2c $(PLC_DIR)/$*/$*.st && \
	mv -f $(BUILD_FILES) ./core/ && \
	./build_core.sh && \
	mv ./core/openplc $(PLC_DIR)/$*/openplc
