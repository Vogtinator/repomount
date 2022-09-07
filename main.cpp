/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2022 Fabian Vogt <fabian@suse.de>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <dirent.h>
#include <sys/epoll.h>
#include <sys/inotify.h>

#include <string>

#include "repovfs.h"

// For argument parsing. First argument is the mountpoint
// (handled by libfuse, but this needs to skip it) and the
// others are rpm files or directories.
struct repomount_opts {
    bool mountpoint_seen = false;
    std::vector<std::string> rpms;
};

int processOption(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    (void)outargs;
    if (key != FUSE_OPT_KEY_NONOPT)
        return 1;

    auto *opts = static_cast<repomount_opts *>(data);
    // Skip the mountpoint
    if (!opts->mountpoint_seen) {
        opts->mountpoint_seen = true;
        return 1;
    }

    opts->rpms.emplace_back(arg);
    return 0;
}

int main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_cmdline_opts opts;
    repomount_opts rmOpts;
    fuse_opt_parse(&args, &rmOpts, nullptr, processOption);
    if (fuse_parse_cmdline(&args, &opts) != 0)
        return 1;

    if (opts.show_help || !opts.mountpoint || rmOpts.rpms.empty()) {
        printf("Usage: %s [options] <mountpoint> <rpm file>...\n\n", argv[0]);
        fuse_cmdline_help();
        fuse_lowlevel_help();
        return opts.show_help ? 0 : 1;
    } else if (opts.show_version) {
        printf("RepoMount version 0.1\n");
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        return 0;
    }

    RepoVFS vfs;
    struct RpmDirWatch {
        std::string path;
        int inotifyWatch;
    };

    std::vector<RpmDirWatch> rpmdirs;

    // Add all given RPMs to the VFS
    for (auto &rpm : rmOpts.rpms) {
        struct stat s;
        if (stat(rpm.c_str(), &s) != 0) {
            fprintf(stderr, "Failed to open %s: %s\n", rpm.c_str(), strerror(errno));
            return 1;
        }

        // If the given path is a directory, add all .rpm files
        if (S_ISDIR(s.st_mode)) {
            DIR *d = opendir(rpm.c_str());
            rpmdirs.push_back({rpm, -1});
            if (!d) {
                fprintf(stderr, "Failed to open %s: %s\n", rpm.c_str(), strerror(errno));
                return 1;
            }
            for (auto *entry = readdir(d); entry; entry = readdir(d)) {
                if (std::string_view(entry->d_name).ends_with(".rpm")) {
                    if (!vfs.addRPM(rpm + "/" + entry->d_name)) {
                        fprintf(stderr, "Failed to add %s\n", entry->d_name);
                        return 1;
                    }
                }
            }
            closedir(d);
        } else {
            if (!vfs.addRPM(rpm)) {
                fprintf(stderr, "Failed to add %s\n", rpm.c_str());
                return 1;
            }
        }
    }

    if(!vfs.mount(args, opts.mountpoint))
        return 1;

    const int fuseFD = vfs.fuseFD();
    // Set the FD to O_NONBLOCK so that it can be read in a loop until empty
    int flags = fcntl(fuseFD, F_GETFL);
    fcntl(fuseFD, F_SETFL, flags | O_NONBLOCK);

    const int inotifyFD = inotify_init1(IN_NONBLOCK);
    if(inotifyFD < 0) {
        perror("inotify_init1");
        return 1;
    }

    for(auto &dir : rpmdirs)
        dir.inotifyWatch = inotify_add_watch(inotifyFD, dir.path.c_str(), IN_CLOSE_WRITE);

    #define MAX_EVENTS 10
    struct epoll_event ev, events[MAX_EVENTS];

    int epollfd = epoll_create1(0);
    if (epollfd < -1) {
        perror("epoll_create1");
        return 1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = fuseFD;
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, fuseFD, &ev) == -1) {
        perror("epoll_ctl");
        return 1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = inotifyFD;
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, inotifyFD, &ev) == -1) {
        perror("epoll_ctl");
        return 1;
    }

    while(!fuse_session_exited(vfs.fuseSession)) {
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if(nfds < -1) {
            if(errno == EINTR)
                continue;

            perror("epoll_wait");
            return 1;
        }

        for (int i = 0; i < nfds; ++i) {
           if (events[i].data.fd == fuseFD) {
               if(!vfs.processFuseRequests()) {
                   perror("processing FUSE request");
                   return 1;
               }
           } else if(events[i].data.fd == inotifyFD) {
                char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
                const struct inotify_event *event;
                ssize_t len;

                len = read(inotifyFD, buf, sizeof(buf));
                if(len == -1 && errno != EAGAIN) {
                    perror("read");
                    return 1;
                }

                if(len <= 0)
                    continue;

                for(char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
                    event = (const struct inotify_event *) ptr;
                    for(auto &dir : rpmdirs) {
                        if(dir.inotifyWatch == event->wd) {
                            auto path = dir.path + "/" + event->name;
                            if(path.ends_with(".rpm")) {
                                if(!vfs.addRPM(path))
                                    fprintf(stderr, "Failed to add %s\n", path.c_str());
                            }
                            break;
                        }
                    }
                }
           }
        }
    }

    fuse_opt_free_args(&args);
    return 0;
}
