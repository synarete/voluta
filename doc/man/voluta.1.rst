.. SPDX-License-Identifier: GPL-3.0-or-later

========
 voluta
========

-----------------------
secure content archiver
-----------------------

:Author:         Shachar Sharon
:Date:           Sep 2020
:Copyright:      GPLv3
:Manual section: 1
:Manual group:   Voluta Manual

..


SYNOPSIS
========

  **voluta** <command> [options]


DESCRIPTION
===========
**voluta** is a user-space file-system encapsulated within a regular file.

The layout of the underlying volume is arranged as packed archive, which may be
easily converted to objects representation.


COMMANDS
========

..

mkfs
----

**voluta mkfs** -s <size> *pathname*

..

Format new voluta file-system volume over regular file at *pathname*. The *-s*,
*--size* option defines the volume's size in bytes. Size may be suffixed with
*G* to denote giga-bytes. The minimum volume size is 1G and maximum is 1T.
Upon creation the user is requested to provide secure passphrase which is used
for encryption of file-system's main key. This passphrase is later required for
all other commands which access this volume.

..

|
| *-s*, *--size=SIZE*
|  Size of new volume in bytes
|
| *-P*, *--passphrase-file=FILE*
|  Passphrase file. This option should be considered insecure. Avoid it.
|


mount
-----
**voluta mount** [--no-daemon] *pathname* *mountpoint*

Start a user-space daemon which mounts *voluta* volume as FUSE file system.
The regular file *pathname* must refer to a previously formatted volume with
**mkfs**, and *mountpoint* must be an empty directory. Upon start, the user
is requested to provide the passphrase which was used upon volume's *mkfs*.


..

umount
------
**voluta umount** [--force] *mountpoint*

..

clone
-----
**voluta clone** [options] *mountpoint* *pathname*

..


archive
-------
**voluta archive** *volume-file* *archive-dir*

..


restore
-------
**voluta restore** *archive-file* *volume-dir*

..


BUGS
====

Still a work-in-progress. Do not use in production.



SEE ALSO
========

**mount**\(8)

..


