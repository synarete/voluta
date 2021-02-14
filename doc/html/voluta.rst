===============================
 Voluta -- a File-System Vault
===============================

.. contents:: :depth: 2

.. sectnum::

----------
 Overview
----------


What is Voluta?
~~~~~~~~~~~~~~~
Voluta is an encrypted file-system in user-space. Using it, a user can store
large data-sets within single regular file "vault", either with inline or
offline encryption. She may also archive an entire file-system into an
encrypted objects representation, which can later be shipped into remote
cloud provider.

As an example, consider the case of storing the home directory of different
users under an isolated namespaces, each encrypted with its own unique private
key. Alternatively, executing fully encrypted containers, where their entire
data-set is stored in a single file.

Unlike many in-kernel file-systems, voluta uses regular file as its backing
storage volume, instead of raw block device. It also tries to pack the data
into the file without leaving holes, instead of spreading it all over the
device. Thus, for mostly append workloads, the file size correlates to the
amount of data used by a voluta file-system. When the backing storage file
resides on a file-system which supports the ``copy_file_range(2)`` system
call (such as ``XFS`` or ``BTRFS``), voluta also support instant file-system
clones.


What is Voluta not?
~~~~~~~~~~~~~~~~~~~
Voluta can not be used as a root file-system, nor was it designed to serve as
a high performance storage system. While a lot of effort has been made to
minimize the penalty of user-space file-system (especially when not using
inline encryption), its data-packing strategy and usage of regular file as
backing storage implies performance degradation compared to in-kernel
file-systems.


Encryption mode
~~~~~~~~~~~~~~~
TODO


System requirements
~~~~~~~~~~~~~~~~~~~
Voluta is implemented for the GNU/Linux environment. It requires ``FUSE-7.31``
or higher, and ``libgcrypt-1.8.0`` or higher. Currently tested on ``x86_64``
architecture only.


-------------------
 Build and Install
-------------------

Preparation
~~~~~~~~~~~

Clone voluta's source code:

.. code-block:: sh

  $ git clone https://github.com/synarete/voluta


Depending on your system, you may need to install additional development
packages in order to compile voluta from source.

On rpm-based systems, install the following packages:

.. code-block:: sh

  $ # run as privileged user:
  $ dnf install gcc make automake libtool libuuid-devel libattr-devel
  $ dnf install libcap-devel libunwind-devel libgcrypt-devel kernel-headers
  $ dnf install python3-docutils

On deb-based systems, install the following packages:

.. code-block:: sh

  $ # run as privileged user:
  $ apt-get install gcc make automake libtool uuid-dev attr-dev libcap-dev
  $ apt-get install libunwind-dev libgcrypt-dev kernel-headers
  $ apt-get install python3-docutils


Build with GNU/autotools
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: sh

  $ git clone https://github.com/synarete/voluta
  $ cd voluta
  $ ./bootstrap
  $ cd build
  $ ../configure
  $ make
  $ make install


Build as rpm/deb package
~~~~~~~~~~~~~~~~~~~~~~~~
On rpm/deb system, you may try installtion via package managers. A helper
script is provided to build packages:

.. code-block:: sh

  $ ./pkg/packagize.sh
  ...

When done, packages are located under ``build`` directory, and should be
installed by privileged user.


-------
 Usage
-------

Preparation
~~~~~~~~~~~

Voluta is designed to operate as a non-privileged process. A user can mount
his own isolated file-system, without any need for special resources or
capabilities from the system. However, an appropriate privilege (Linux: the
``CAP_SYS_ADMIN`` capability) is required to mount a voluta filesystem.

Voluta uses a dedicated mounting daemon service, which allows a non-privileged
processes to mount and umount file-systems (similar to ``fusermount3``). As
a security enhancement, only well-known directories, which are listed in
``/etc/voluta/mountd.conf`` configuration file, may be valid as mount point.
Whenever adding new entries to this file, the ``voluta-mountd.service`` must be
restarted for changes to take effect.

Before mounting new file-system, the sysadmin should add new entry to the
local system configuration file:

.. code-block:: sh

  $ echo '/path/to/mount/dir' >> /etc/voluta/mountd.conf
  $ systemctl restart voluta-mountd.service


Creation
~~~~~~~~

Voluta allows users to create both an encrypted and non-encrypted file-system,
where a non-encrypted file-system can be encrypted offline later on, and vise
versa (i.e., an encrypted file-system may be decrypted offline). Upon
creating an encrypted file-system, the user should provide a strong passphrase
which will later be used during the mount process.

The file-system's data resides on a regular file, which the owner of this
volume-file must have read-write access permissions. The maximal file-system
size should be defined upon creation, thou the actual used file-size will be
much smaller.


To format a new encrypted voluta file-system, use the ``mkfs`` sub-command:

.. code-block:: sh

  $ voluta mkfs --encrypted --size=SIZE /path/to/volume/name.voluta
  enter passphrase:
  re-enter passphrase:
  ...


To format a non-encrypted voluta file-system, use the ``mkfs`` sub-command
without the ``--encrypted`` option.


Mounting
~~~~~~~~

Mounting a voluta file-system can be made only when all the following
conditions are met:

1. The target mount directory is empty.
2. User has read-write-execute access to the mount directory.
3. The mount directory is listed in ``/etc/voluta/mountd.conf`` file.
4. System-wide ``voluta-mountd.service`` is active.

To mount a previously formatted voluta file-system, use the ``mount``
sub-command:

.. code-block:: sh

  $ voluta mount /path/to/volume/fsname.voluta /path/to/mount/dir


Depending on volume's size, encryption mode and local system's characteristics,
mount should be active within few seconds:

.. code-block:: sh

  $ df -h /path/to/mount/dir


To unmount a live volute file-system, use the ``umount`` sub-command (note that
the ``voluta-mountd.service`` must be active):

.. code-block:: sh

  $ systemctl status voluta-mountd.service
  $ voluta umount /path/to/mount/dir


Cloning
~~~~~~~
When the underlying volume file residues within a file-system which supports
the ``copy_file_range(2)`` system call (such as ``XFS`` or ``BTRFS``), a user
my create a writable snapshot of an active file-system:

.. code-block:: sh

  $ voluta clone /path/to/mount/dir /path/to/volume/fsclone.voluta


Note that the target cloned volume file must reside on the file-system as
the original volume.


Offline encryption
~~~~~~~~~~~~~~~~~~
A user choose to run a voluta file-system in non-encryption mode, primarly
when she wants to avoid the run-time performance penalty of copy and encryption
of data. In such cases, it may be desired to encrypt the underlying volume in
offline mode (encryption is done in-place):

.. code-block:: sh

  $ voluta encrypt /path/to/volume/fsname.voluta
  enter passphrase:
  re-enter passphrase:
  ...


The reversed operation is also valid: take an encrypted volume and decrypt it
in-place:

.. code-block:: sh

  $ voluta decrypt /path/to/volume/fsname.voluta
  enter passphrase:


Archiving
~~~~~~~~~
It is often desired to archive large voluta volumes as encrypted objects
represnations, which may be shipped to remote machine or remote cloud. Voluta
provides a mechanism to export and import:

.. code-block:: sh

  $ voluta export /path/to/volume/fsname.voluta /pash/to/repo/dir
  $ voluta import /pash/to/repo/dir/fsname.voluta /path/to/volume/dir


---------
 Design
---------
TODO


---------
 License
---------
Voluta is distributed under **GPL-3.0-or-later** license. It is a free
software: you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

Voluta is distributed in the hope that it will be useful, but without any
warranty; without even the implied warranty of merchantability or fitness
for a particular purpose. You should have received a copy of the GNU General
Public License along with this program. If not, see GPLv3_


.. _GPLv3: https://www.gnu.org/licenses/gpl-3.0.en.html




