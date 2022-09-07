/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2022 Fabian Vogt <fabian@suse.de>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <fuse_lowlevel.h>
#include <string>
#include <map>
#include <ranges>
#include <sys/stat.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmlog.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "repovfs.h"

template <typename T> struct Defer {
    Defer(T t) : t(t) {}
    ~Defer() { t(); }
    T t;
};

struct RepoVFS::Node {
    // Creates a new node. Make sure to set the node's stat.st_ino once inserted.
    Node(fuse_ino_t parentIno, const struct stat &stat) :
        parentIno(parentIno),
        stat(stat)
    {}

    virtual ~Node() {}

    // In the case of hardlinked files this might not be the entire truth.
    fuse_ino_t parentIno;
    struct stat stat;
};

struct RepoVFS::DirNode : public RepoVFS::Node {
    using Node::Node;
    std::map<std::string, fuse_ino_t, std::less<>> children;

    // Set to true if at least one package owns this.
    // This allows reading in RPMs in arbitrary order,
    // filling in missing directory metainfo when it arrives.
    bool packageOwned = false;
};

struct RepoVFS::FileNode : public RepoVFS::Node {
    using Node::Node;
};

struct RepoVFS::SymlinkNode : public RepoVFS::Node {
    using Node::Node;
    std::string target;
};

RepoVFS::DirNode* RepoVFS::makeDirNode(fuse_ino_t parent) {
    struct stat attr = {
        .st_ino = nodes.size(),
        .st_nlink = 1,
        .st_mode = S_IFDIR | 0755,
        .st_uid = 0,
        .st_gid = 0,
        .st_size = 0,
        .st_blksize = 512,
        .st_blocks = 0,
    };
    clock_gettime(CLOCK_REALTIME, &attr.st_atim);
    attr.st_mtim = attr.st_atim;
    attr.st_ctim = attr.st_atim;

    auto node = std::make_unique<DirNode>(parent, attr);
    auto ret = node.get();
    nodes.push_back(std::move(node));
    return ret;
}

RepoVFS::RepoVFS()
{
    rpmReadConfigFiles(NULL, NULL);
    ts = rpmtsCreate();

    // inode 0 is invalid
    nodes.push_back(nullptr);

    // inode 1 is the root
    makeDirNode(0);
}

RepoVFS::~RepoVFS()
{
    rpmtsFree(ts);
}

bool RepoVFS::addRPM(const std::string &path)
{
    // Open the RPM file
    auto f = Fopen(path.c_str(), "r.ufdio");
    if (Ferror(f)) {
        rpmlog(RPMLOG_ERR, "%s: %s\n", path.c_str(), Fstrerror(f));
        return false;
    }
    auto ffree = Defer([&] { Fclose(f); });

    // Read the header
    Header hdr;
    if(int rc = rpmReadPackageFile(ts, f, path.c_str(), &hdr); rc != RPMRC_OK) {
        rpmlog(RPMLOG_ERR, "%s: %d", path.c_str(), rc);
        return false;
    }

    // Iterate all files
    rpmfi fi = rpmfiNew(ts, hdr, RPMTAG_BASENAMES, RPMFI_NOHEADER | RPMFI_FLAGS_QUERY);
    auto fifree = Defer([&] { rpmfiFree(fi); });

    fi = rpmfiInit(fi, 0);
    while (rpmfiNext(fi) >= 0) {
        // Ignore %ghost files
        if(rpmfiFFlags(fi) & RPMFILE_GHOST)
            continue;

        // This does quite a bit of work for us already,
        // even translating uid/gid with proper fallback.
        struct stat stat;
        if(rpmfiStat(fi, 0, &stat) != 0)
            return false;

        const char *fn = rpmfiFN(fi);
        if(!fn || fn[0] != '/') {
            rpmlog(RPMLOG_WARNING, "Filename %s is weird, ignoring\n", fn);
            continue;
        }
        fn++; // Skip the /

        // Go through the path for each component
        auto *currentDirNode = dynamic_cast<DirNode*>(nodes[1].get());
        std::ranges::split_view components{std::string_view(fn), '/'};
        for(auto it = begin(components); it != end(components);) {
            auto range = *it;
            std::string_view component(range.begin(), range.end());
            ++it;

            auto thisNode = nodeByName(currentDirNode, component);
            if(it != end(components)) {
                // Not the final component, traverse it.
                // Create placeholder directory if necessary.
                if(!thisNode) {
                    // Parent directory not found, create it
                    thisNode = makeDirNode(currentDirNode->stat.st_ino);
                    currentDirNode->children[std::string(component)] = thisNode->stat.st_ino;
                    currentDirNode = dynamic_cast<DirNode*>(thisNode);
                    rpmlog(RPMLOG_NOTICE, "Created placeholder directory %s\n", );
                } else if(auto dirNode = dynamic_cast<DirNode*>(thisNode)) {
                    // Parent directory exists, use it
                    currentDirNode = dirNode;
                } else {
                    // Node exists, but isn't a directory
                    rpmlog(RPMLOG_ERR, "Component %s of %s not a directory\n", std::string(component).c_str(), fn);
                    return false;
                }
                continue;
            }

            if(thisNode) {
                // Node already exists, only allowed for directories
                if(!S_ISDIR(stat.st_mode) || !S_ISDIR(thisNode->stat.st_mode)) {
                    rpmlog(RPMLOG_ERR, "%s has type mismatch", fn);
                    return false;
                }

                auto dirNode = dynamic_cast<DirNode*>(thisNode);
                if(dirNode->packageOwned) {
                    if(dirNode->stat.st_mode != stat.st_mode)
                        rpmlog(RPMLOG_WARNING, "Conflicting modes for dir %s\n", fn);
                    if(dirNode->stat.st_uid != stat.st_uid
                       || dirNode->stat.st_gid != stat.st_gid)
                        rpmlog(RPMLOG_WARNING, "Conflicting owner for dir %s\n", fn);
                    // TODO: Check other attributes?
                } else {
                    // Wasn't owned previously, take ownership.
                    stat.st_ino = dirNode->stat.st_ino;
                    dirNode->stat = stat;
                    dirNode->packageOwned = true;
                }
                continue;
            }

            // Node doesn't exist yet, create it
            stat.st_ino = nodes.size();
            if(S_ISDIR(stat.st_mode)) {
                nodes.push_back(std::make_unique<DirNode>(currentDirNode->stat.st_ino, stat));
            } else if(S_ISREG(stat.st_mode)) {
                nodes.push_back(std::make_unique<FileNode>(currentDirNode->stat.st_ino, stat));
            } else if(S_ISLNK(stat.st_mode)) {
                auto target = rpmfiFLink(fi);
                if(!target || target[0] == '/') {
                    rpmlog(RPMLOG_WARNING, "Symlink %s -> %s unhanlded\n", fn, target);
                    continue;
                }

                auto node = std::make_unique<SymlinkNode>(currentDirNode->stat.st_ino, stat);
                node->target = target;
                nodes.push_back(std::move(node));
            } else {
                rpmlog(RPMLOG_WARNING, "Mode %o not handled for file %s\n", stat.st_mode, fn);
            }

            currentDirNode->children[std::string(component)] = stat.st_ino;
        }
    }

    dumpTree(dynamic_cast<DirNode*>(nodes[1].get()));

    return true;
}

bool RepoVFS::mountAndLoop(const std::string &path)
{
    return false;
}

RepoVFS::Node *RepoVFS::nodeByName(const DirNode *parentDir, const std::string_view &name)
{
    if(auto it = parentDir->children.find(name); it != parentDir->children.end())
        return nodes[it->second].get();

    return nullptr;
}

void RepoVFS::dumpTree(const DirNode *node, int level)
{
    for(auto child : node->children) {
        for(int i = 0; i < level; ++i)
            rpmlog(RPMLOG_NOTICE, "\t");

        auto childNode = nodes[child.second].get();
        if(auto dirChild = dynamic_cast<DirNode*>(childNode)) {
            rpmlog(RPMLOG_NOTICE, "%s\n", child.first.c_str());
            dumpTree(dirChild, level + 1);
        } else if(auto symlinkChild = dynamic_cast<SymlinkNode*>(childNode)) {
            rpmlog(RPMLOG_NOTICE, "%s -> %s\n", child.first.c_str(), symlinkChild->target.c_str());
        } else {
            rpmlog(RPMLOG_NOTICE, "%s\n", child.first.c_str());
        }
    }
}
