# Voluta: Encrypted file-system vault

## Overview
Voluta is an encrypted user-space file-system, encapsulated within a regular 
file. It encrypts both data and meta-data, either online or offline, which is 
useful for cases of large data-sets shifting or archiving, as well as
containers encapsulation.

Voluta is implemented for the GNU/Linux environment, using FUSE-7.31 or higher. 


## License 
GPL-3.0-or-later


## Build

Using autotools:

```console
  $ ./bootstrap
  $ ./configure
  $ make
  $ make install
```

Using dnf/rpm:

```console
  $ ./pkg/packagize-rpm.sh
  $ dnf install ./build/voluta-*.rpm
```

## Howto

```console
  $ systemctl start voluta-mountd.service  # as root
  $ voluta mkfs -s 64G /path/to/file/data.voluta
  $ voluta mount /path/to/file/data.voluta /path/to/mount/dir
  ...
  $ df -h | grep voluta
  ...
  $ voluta umount /path/to/mount/dir
```
