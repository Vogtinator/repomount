/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2022 Fabian Vogt <fabian@suse.de>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <dirent.h>

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

    int ret = vfs.mountAndLoop(args, opts.mountpoint) ? 0 : 1;
    fuse_opt_free_args(&args);
    return ret;
}
