.. SPDX-License-Identifier: GPL-3.0-or-later

===============
 voluta-mountd
===============

------------------------
voluta's mounting daemon
------------------------

:Author:         Shachar Sharon
:Date:           Feb 2021
:Copyright:      GPLv3
:Manual section: 8
:Manual group:   Voluta Manual

..


SYNOPSIS
========

  **voluta-mountd** -f <mount-rules.conf>


DESCRIPTION
===========
The **voluta-mountd** program is a server side daemon helper to
**voluta mount**. As the **mount**\(2) system call requires appropriate
privilege (Linux: the **CAP_SYS_ADMIN** capability), a special auxiliary
daemon service provides a non-privileged voluta the mount and umount
functionality.

Only directories which are listed in the **mount-rules.conf** input file
are valid mount points.


BUGS
====

Still a work-in-progress. Do not use in production.



SEE ALSO
========

**voluta**\(1) **mount**\(8)

..


