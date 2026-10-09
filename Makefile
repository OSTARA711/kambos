# File: ~/kambos/Makefile

CC = gcc
PKG_CONFIG ?= pkg-config

CFLAGS ?= -O2
CFLAGS += -Wall -Wextra

GTK_CFLAGS := $(shell $(PKG_CONFIG) --cflags gtk+-3.0)
GTK_LIBS := $(shell $(PKG_CONFIG) --libs gtk+-3.0)
LDLIBS += $(GTK_LIBS) -lsodium -lssl -lcrypto -pthread

PREFIX ?= /usr
DESTDIR ?=

BINDIR = $(PREFIX)/bin
DESKTOPDIR = $(PREFIX)/share/applications
ICONDIR = $(PREFIX)/share/icons/hicolor
APPICON = kambos

TARGET = kambos

.PHONY: all check-deps install install-icons uninstall clean

all: $(TARGET)

# Check required build dependencies.
check-deps:
	@command -v $(CC) >/dev/null 2>&1 || { echo "Error: $(CC) is not installed."; exit 1; }
	@command -v $(PKG_CONFIG) >/dev/null 2>&1 || { echo "Error: pkg-config is not installed."; exit 1; }
	@$(PKG_CONFIG) --exists gtk+-3.0 || { echo "Error: GTK3 development files are missing."; exit 1; }
	@pkg-config --exists libsodium openssl || { echo "Error: libsodium or OpenSSL development files are missing."; exit 1; }

$(TARGET): kambos.c | check-deps
	$(CC) $(CPPFLAGS) $(CFLAGS) $(GTK_CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

# Install the application.
install: $(TARGET) install-icons
	install -Dm755 $(TARGET) "$(DESTDIR)$(BINDIR)/$(TARGET)"
	install -Dm644 kambos.desktop "$(DESTDIR)$(DESKTOPDIR)/kambos.desktop"
ifeq ($(DESTDIR),)
	@if command -v update-desktop-database >/dev/null 2>&1; then \
		update-desktop-database "$(DESKTOPDIR)"; \
	fi
endif

# Install application icons.
install-icons:
	install -Dm644 kambos.svg "$(DESTDIR)$(ICONDIR)/scalable/apps/$(APPICON).svg"
	install -Dm644 kambos_256x256.png "$(DESTDIR)$(ICONDIR)/256x256/apps/$(APPICON).png"
	install -Dm644 kambos_128x128.png "$(DESTDIR)$(ICONDIR)/128x128/apps/$(APPICON).png"
	install -Dm644 kambos_64x64.png "$(DESTDIR)$(ICONDIR)/64x64/apps/$(APPICON).png"
ifeq ($(DESTDIR),)
	@if command -v gtk-update-icon-cache >/dev/null 2>&1; then \
		gtk-update-icon-cache -f "$(ICONDIR)"; \
	fi
endif

# Uninstall the application and its icons.
uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"
	rm -f "$(DESTDIR)$(DESKTOPDIR)/kambos.desktop"
	rm -f "$(DESTDIR)$(ICONDIR)/scalable/apps/$(APPICON).svg"
	rm -f "$(DESTDIR)$(ICONDIR)/256x256/apps/$(APPICON).png"
	rm -f "$(DESTDIR)$(ICONDIR)/128x128/apps/$(APPICON).png"
	rm -f "$(DESTDIR)$(ICONDIR)/64x64/apps/$(APPICON).png"
ifeq ($(DESTDIR),)
	@if command -v gtk-update-icon-cache >/dev/null 2>&1; then \
		gtk-update-icon-cache -f "$(ICONDIR)"; \
	fi
	@if command -v update-desktop-database >/dev/null 2>&1; then \
		update-desktop-database "$(DESKTOPDIR)"; \
	fi
endif

# Remove the compiled binary.
clean:
	rm -f $(TARGET)
