RepoMount
=========

FUSE filesystem to mount contents of RPM packages.

Building
--------

To build this, a C++20 compiler, CMake >= 3.6 and librpm as well as libfuse3 development packages need to be installed.

```
cmake -B build
cmake --build build
cmake --install build
```

Usage
-----

```
Usage: ./repomount [options] <mountpoint> <rpm file>...

    -o allow_other         allow access by all users
    -o allow_root          allow access by root
    -o auto_unmount        auto unmount on process termination
```

Multiple paths to RPM files and directories containing `.rpm` files can be supplied.
They will be scanned and the filesystem containing the content of all packages mounted
at the given mountpoint. To unmount, use `fusermount3 -u <mountpoint>`, `umount` or
send `SIGINT` to the `repomount` process e.g. by pressing `Ctrl-C`.

File conflicts between packages are not allowed. Other conflicts raise warnings,
but will not prevent mounting.

Example for chrooting into a small system from downloaded RPM packages:

```
> zypper --root $PWD/repomount-root --reposd-dir /etc/zypp/repos.d/ in --download-only aaa_base bash
[...]

The following NEW product is going to be installed:
  "openSUSE Tumbleweed"

82 new packages to install.
Overall download size: 26.6 MiB. Already cached: 0 B. Download only.
Continue? [y/n/v/...? shows all options] (y): y
[...]
> ll repomount-root/var/cache/zypp/packages/openSUSE-20180203-0/x86_64/
total 26540
-rw-r--r-- 1 fvogt users   90162 Sep  8 09:31 aaa_base-84.87+git20220727.43b9e53-1.2.x86_64.rpm
-rw-r--r-- 1 fvogt users   34518 Sep  8 09:31 aaa_base-extras-84.87+git20220727.43b9e53-1.2.x86_64.rpm
-rw-r--r-- 1 fvogt users  667526 Sep  8 09:31 bash-5.1.16-8.3.x86_64.rpm
-rw-r--r-- 1 fvogt users   25152 Sep  8 09:31 bash-sh-5.1.16-8.3.x86_64.rpm
-rw-r--r-- 1 fvogt users  694159 Sep  8 09:31 busybox-1.35.0-5.2.x86_64.rpm
-rw-r--r-- 1 fvogt users  409134 Sep  8 09:31 chkstat-1599_20220713-31.3.x86_64.rpm
-rw-r--r-- 1 fvogt users  294852 Sep  8 09:31 compat-usrmerge-tools-84.87-5.12.x86_64.rpm
[...]
> mkdir repomount-mnt
> repomount -o ro repomount-mnt repomount-root/var/cache/zypp/packages/*/*/ &
[1] 5400
> unshare -mUR repomount-mnt
-bash: /dev/null: Read-only file system
-bash: /dev/null: Read-only file system
-bash: /dev/null: Read-only file system
-bash: /dev/null: Read-only file system
-bash: /dev/null: Read-only file system
-bash: /dev/null: Read-only file system
fvogt@linux-e202.suse.de:/> /usr/bin/ls --help
BusyBox v1.35.0 () multi-call binary.

Usage: ls [-1AaCxdLHRFplinshrSXvctukZ] [-w WIDTH] [FILE]...
[...]
fvogt@linux-e202.suse.de:/> cat /etc/os-release
NAME="openSUSE Tumbleweed"
# VERSION="20220906"
[...]
fvogt@linux-e202.suse.de:/> exit
logout
> fg
repomount -o ro repomount-mnt repomount-root/var/cache/zypp/packages/*/*/
^C
```

How it works
------------

On startup, repomount visits every RPM package (in random order) and reads their header content to
build an internal filesystem tree. This consists of directories (`DirNode`), files (`FileNode`) and
symlinks (`SymlinkNode`). They get added to a vector of nodes, using the (incrementing) inode number
as index. Directory nodes have a map of filename -> inode to address their children. This design
allows a rather simple implementation of the FUSE entry points.

Read access to files is currently implemented in a trivial but incredibly inefficient way. Every
file node stores a path to the containing package as well as its path inside the package. To perform
the read, the RPM package is opened and the (potentially compressed) payload iterated until the file
is found and the requested data returned.

TODO
----

- Optimize performance of read requests
- Support for absolute symlink targets  
  (maybe? If it was installed with `rpm --root` they'd be pointing to the "wrong" path as well)
- Allow adding new RPMs while the filesystem is mounted by watching directories with inotify
  (a PoC is implemented in the `inotify` branch)