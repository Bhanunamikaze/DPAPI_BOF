# SharpDPAPI BOF Port — Makefile
# Cross-compilation from Linux using MinGW-w64

CC = x86_64-w64-mingw32-gcc
AR = x86_64-w64-mingw32-ar

CFLAGS = -c -Os -Wall -DBOF -I include
LDFLAGS =

# Directories
SRC_COMMON = src/common
SRC_BOFS   = src/bofs
INCLUDE    = include
DIST       = dist
OBJ_DIR    = obj

# Common library sources
COMMON_SRCS = $(wildcard $(SRC_COMMON)/*.c)
COMMON_OBJS = $(patsubst $(SRC_COMMON)/%.c, $(OBJ_DIR)/%.o, $(COMMON_SRCS))

# BOF sources
BOF_SRCS = $(wildcard $(SRC_BOFS)/*.c)
BOF_TARGETS = $(patsubst $(SRC_BOFS)/%.c, $(DIST)/%.o, $(BOF_SRCS))

# Phony targets
.PHONY: all clean common bofs check-size dirs

all: dirs common bofs check-size

dirs:
	@mkdir -p $(OBJ_DIR) $(DIST)

# ---- Common static library ----
common: dirs $(OBJ_DIR)/dpapi_common.a

$(OBJ_DIR)/%.o: $(SRC_COMMON)/%.c
	$(CC) $(CFLAGS) -o $@ $<

$(OBJ_DIR)/dpapi_common.a: $(COMMON_OBJS)
	$(AR) rcs $@ $^
	@echo "[+] Built dpapi_common.a ($(shell stat -c%s $@ 2>/dev/null || echo '?') bytes)"

# ---- Individual BOFs ----
# Each BOF .o links against the common library objects.
# For BOFs, we compile to a single relocatable object that
# Cobalt Strike can load. We use -r to produce a relocatable
# object that includes all needed symbols.
bofs: common $(BOF_TARGETS)

$(DIST)/%.o: $(SRC_BOFS)/%.c $(OBJ_DIR)/dpapi_common.a
	$(CC) $(CFLAGS) -o $(OBJ_DIR)/$*_bof.o $<
	x86_64-w64-mingw32-ld -r -o $@ $(OBJ_DIR)/$*_bof.o $(COMMON_OBJS)
	@echo "[+] Built $@ ($(shell stat -c%s $@ 2>/dev/null || echo '?') bytes)"

# ---- Size check ----
MAX_SIZE = 307200  # 300KB

check-size:
	@echo ""
	@echo "=== BOF Size Report ==="
	@for f in $(DIST)/*.o; do \
		if [ -f "$$f" ]; then \
			size=$$(stat -c%s "$$f"); \
			name=$$(basename "$$f"); \
			if [ $$size -gt $(MAX_SIZE) ]; then \
				echo "  [FAIL] $$name: $$size bytes (> 300KB)"; \
			else \
				echo "  [ OK ] $$name: $$size bytes"; \
			fi; \
		fi; \
	done
	@echo "======================="

# ---- Clean ----
clean:
	rm -rf $(OBJ_DIR) $(DIST)/*.o
	@echo "[+] Cleaned build artifacts"

# ---- Individual BOF targets for convenience ----
masterkeys: dirs common $(DIST)/masterkeys.o
credentials: dirs common $(DIST)/credentials.o
vaults: dirs common $(DIST)/vaults.o
blob: dirs common $(DIST)/blob.o
backupkey: dirs common $(DIST)/backupkey.o
certificates: dirs common $(DIST)/certificates.o
rdg: dirs common $(DIST)/rdg.o
keepass: dirs common $(DIST)/keepass.o
ps: dirs common $(DIST)/ps.o
triage_bof: dirs common $(DIST)/triage_bof.o
search: dirs common $(DIST)/search.o
sccm: dirs common $(DIST)/sccm.o
machinemasterkeys: dirs common $(DIST)/machinemasterkeys.o
machinecredentials: dirs common $(DIST)/machinecredentials.o
machinevaults: dirs common $(DIST)/machinevaults.o
machinetriage: dirs common $(DIST)/machinetriage.o
chrome_logins: dirs common $(DIST)/chrome_logins.o
chrome_cookies: dirs common $(DIST)/chrome_cookies.o
chrome_statekeys: dirs common $(DIST)/chrome_statekeys.o
