CC = gcc
CFLAGS = -Wall -O2 `pkg-config --cflags gtk+-3.0`
LDFLAGS = `pkg-config --libs gtk+-3.0` -lsodium -lssl -lcrypto -pthread

PREFIX = /usr
BINDIR = $(PREFIX)/bin
DESKTOPDIR = $(PREFIX)/share/applications
ICONDIR = $(PREFIX)/share/icons/hicolor
APPICON = kambos

all: kambos

kambos: kambos.c
$(CC) -o kambos kambos.c $(CFLAGS) $(LDFLAGS)

install: kambos install-icons
# Install binary
sudo install -m 0755 kambos $(BINDIR)/kambos

```
# Install desktop entry
sudo install -m 0644 kambos.desktop $(DESKTOPDIR)/kambos.desktop

# Update desktop database
if [ -x /usr/bin/update-desktop-database ]; then sudo update-desktop-database; fi
```

install-icons:
# Scalable SVG
sudo install -Dm644 kambos.svg $(ICONDIR)/scalable/apps/$(APPICON).svg
# PNG sizes
sudo install -Dm644 kambos_256x256.png $(ICONDIR)/256x256/apps/$(APPICON).png
sudo install -Dm644 kambos_128x128.png $(ICONDIR)/128x128/apps/$(APPICON).png
sudo install -Dm644 kambos_64x64.png  $(ICONDIR)/64x64/apps/$(APPICON).png
# Refresh icon cache
if [ -x /usr/bin/gtk-update-icon-cache ]; then sudo gtk-update-icon-cache -f $(ICONDIR); fi

uninstall:
# Remove binary
sudo rm -f $(BINDIR)/kambos

```
# Remove icons
sudo rm -f $(ICONDIR)/scalable/apps/$(APPICON).svg
sudo rm -f $(ICONDIR)/256x256/apps/$(APPICON).png
sudo rm -f $(ICONDIR)/128x128/apps/$(APPICON).png
sudo rm -f $(ICONDIR)/64x64/apps/$(APPICON).png

# Remove desktop entry
sudo rm -f $(DESKTOPDIR)/kambos.desktop

# Refresh caches
if [ -x /usr/bin/gtk-update-icon-cache ]; then sudo gtk-update-icon-cache -f $(ICONDIR); fi
if [ -x /usr/bin/update-desktop-database ]; then sudo update-desktop-database; fi
```

clean:
rm -f kambos

.PHONY: all install uninstall clean install-icons
