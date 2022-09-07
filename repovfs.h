/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2022 Fabian Vogt <fabian@suse.de>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#pragma once

#include <fuse_lowlevel.h>
#include <memory>
#include <rpm/rpmts.h>
#include <string_view>
#include <vector>

class RepoVFS {
    struct Node;
    struct DirNode;
    struct FileNode;
    struct SymlinkNode;

public:
    RepoVFS();
    ~RepoVFS();
    bool addRPM(const std::string &path);
    bool mount(fuse_args &args, const std::string &path);
    int fuseFD();
    bool processFuseRequests();

private:
    // Functions used by fuse_lowlevel_ops
    static void lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
    static void getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    static void readlink(fuse_req_t req, fuse_ino_t ino);
    static void open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
    static void read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *file_info);
    static void opendir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi);
    static void readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);
    static void releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);

private:
    DirNode *makeDirNode(fuse_ino_t parent);
    Node *nodeForIno(fuse_ino_t ino);
    Node *nodeByName(const DirNode *parent, const std::string_view &name);
    [[maybe_unused]] void dumpTree(const DirNode *node, int level = 0);
    void replyEntry(fuse_req_t req, RepoVFS::Node *node);

    /** VFS stuff */
    std::vector<std::unique_ptr<Node>> nodes;

    /** RPM stuff */
    rpmts ts = rpmtsCreate();

    /** FUSE stuff */
    struct FuseLLOps;
    static const FuseLLOps fuse_ll_ops;
public:
    struct fuse_session *fuseSession = nullptr;
};
