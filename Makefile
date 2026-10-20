# File: ~/kambos/Makefile

CC = gcc
PKG_CONFIG ?= pkg-config

CFLAGS ?= -O2
CFLAGS += -Wall -Wextra

CPPFLAGS ?=
LDFLAGS ?=

GTK_CFLAGS := $(shell $(PKG_CONFIG) --cflags gtk+-3.0)
GTK_LIBS := $(shell $(PKG_CONFIG) --libs gtk+-3.0)

LDLIBS += $(GTK_LIBS) -lsodium -lssl -lcrypto -pthread

PREFIX ?= /usr
DESTDIR ?=

BINDIR = $(PREFIX)/bin
DATADIR = $(PREFIX)/share/kambos
DESKTOPDIR = $(PREFIX)/share/applications
ICONDIR = $(PREFIX)/share/icons/hicolor

CSSDIR = $(DATADIR)/css
IMAGEDIR = $(DATADIR)/images

APPICON = kambos
TARGET = kambos

.PHONY: all check-deps install install-icons install-data uninstall clean

all: $(TARGET)

# Check required build dependencies.
check-deps:
	@command -v $(CC) >/dev/null 2>&1 || { echo "Error: $(CC) is not installed."; exit 1; }
	@command -v $(PKG_CONFIG) >/dev/null 2>&1 || { echo "Error: pkg-config is not installed."; exit 1; }
	@$(PKG_CONFIG) --exists gtk+-3.0 || { echo "Error: GTK3 development files are missing."; exit 1; }
	@$(PKG_CONFIG) --exists libsodium openssl || { echo "Error: libsodium or OpenSSL development files are missing."; exit 1; }

# Compile the application, splash screen, sidebar, Settings, and Kryptos.
$(TARGET): kambos.c \
           splash/splash.c splash/splash.h \
           dashboard/sidebar.c dashboard/sidebar.h \
           dashboard/settings/settings.c dashboard/settings/settings.h \
           dashboard/kryptos/kryptos.c dashboard/kryptos/kryptos.h \
           | check-deps
	$(CC) $(CPPFLAGS) $(CFLAGS) $(GTK_CFLAGS) -o $@ \
		kambos.c \
		splash/splash.c \
		dashboard/sidebar.c \
		dashboard/settings/settings.c \
		dashboard/kryptos/kryptos.c \
		$(LDFLAGS) $(LDLIBS)

# Install the application and desktop entry.
install: $(TARGET) install-icons install-data
	install -Dm755 $(TARGET) "$(DESTDIR)$(BINDIR)/$(TARGET)"
	install -Dm644 kambos.desktop "$(DESTDIR)$(DESKTOPDIR)/kambos.desktop"
ifeq ($(DESTDIR),)
	@if command -v update-desktop-database >/dev/null 2>&1; then \
		update-desktop-database "$(DESKTOPDIR)"; \
	fi
endif

# Install application icons into the desktop icon theme.
install-icons:
	install -Dm644 images/kambos.svg "$(DESTDIR)$(ICONDIR)/scalable/apps/$(APPICON).svg"
	install -Dm644 images/kambos_256x256.png "$(DESTDIR)$(ICONDIR)/256x256/apps/$(APPICON).png"
	install -Dm644 images/kambos_128x128.png "$(DESTDIR)$(ICONDIR)/128x128/apps/$(APPICON).png"
	install -Dm644 images/kambos_64x64.png "$(DESTDIR)$(ICONDIR)/64x64/apps/$(APPICON).png"
ifeq ($(DESTDIR),)
	@if command -v gtk-update-icon-cache >/dev/null 2>&1; then \
		gtk-update-icon-cache -f "$(ICONDIR)"; \
	fi
endif

# Install application runtime data.
install-data:
	install -Dm644 css/style.css "$(DESTDIR)$(CSSDIR)/style.css"
	install -Dm644 images/kambos-app.svg "$(DESTDIR)$(IMAGEDIR)/kambos-app.svg"
	install -Dm644 images/kambos.svg "$(DESTDIR)$(IMAGEDIR)/kambos.svg"
	install -Dm644 images/kryptos.svg "$(DESTDIR)$(IMAGEDIR)/kryptos.svg"
	install -Dm644 images/kallas.svg "$(DESTDIR)$(IMAGEDIR)/kallas.svg"
	install -Dm644 images/vault.svg "$(DESTDIR)$(IMAGEDIR)/vault.svg"
	install -Dm644 images/quarantine.svg "$(DESTDIR)$(IMAGEDIR)/quarantine.svg"
	install -Dm644 images/history.svg "$(DESTDIR)$(IMAGEDIR)/history.svg"
	install -Dm644 images/stats.svg "$(DESTDIR)$(IMAGEDIR)/stats.svg"
	install -Dm644 images/users.svg "$(DESTDIR)$(IMAGEDIR)/users.svg"
	install -Dm644 images/settings.svg "$(DESTDIR)$(IMAGEDIR)/settings.svg"
	install -Dm644 images/bugs.svg "$(DESTDIR)$(IMAGEDIR)/bugs.svg"
	install -Dm644 images/news.svg "$(DESTDIR)$(IMAGEDIR)/news.svg"
	install -Dm644 images/exit.svg "$(DESTDIR)$(IMAGEDIR)/exit.svg"
	install -Dm644 images/incognito.svg "$(DESTDIR)$(IMAGEDIR)/incognito.svg"
	install -Dm644 images/translator.svg "$(DESTDIR)$(IMAGEDIR)/translator.svg"
	install -Dm644 images/hotkeys.svg "$(DESTDIR)$(IMAGEDIR)/hotkeys.svg"
	install -Dm644 images/alien.svg "$(DESTDIR)$(IMAGEDIR)/alien.svg"

# Uninstall the application, runtime data, desktop entry, and icons.
uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"
	rm -f "$(DESTDIR)$(DESKTOPDIR)/kambos.desktop"
	rm -f "$(DESTDIR)$(CSSDIR)/style.css"
	rm -f "$(DESTDIR)$(IMAGEDIR)/kambos-app.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/kambos.svg"
	rm -f "$(DESTDIR)$(ICONDIR)/scalable/apps/$(APPICON).svg"
	rm -f "$(DESTDIR)$(ICONDIR)/256x256/apps/$(APPICON).png"
	rm -f "$(DESTDIR)$(ICONDIR)/128x128/apps/$(APPICON).png"
	rm -f "$(DESTDIR)$(ICONDIR)/64x64/apps/$(APPICON).png"
	rm -f "$(DESTDIR)$(IMAGEDIR)/kryptos.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/kallas.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/vault.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/quarantine.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/history.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/stats.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/users.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/settings.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/bugs.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/news.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/exit.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/incognito.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/translator.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/hotkeys.svg"
	rm -f "$(DESTDIR)$(IMAGEDIR)/alien.svg"
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
