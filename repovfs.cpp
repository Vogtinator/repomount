/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2022 Fabian Vogt <fabian@suse.de>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include "repovfs.h"

#include <fuse_lowlevel.h>
#include <grp.h>
#include <pwd.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmlog.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <map>
#include <ranges>
#include <string>

// RAII helper for C types
template <typename T> struct Defer {
    explicit Defer(T t) : t(t) { }
    ~Defer() { t(); }
    T t;
};

struct RepoVFS::FuseLLOps : public fuse_lowlevel_ops {
    FuseLLOps()
    {
        lookup = &RepoVFS::lookup;
        getattr = &RepoVFS::getattr;
        readlink = &RepoVFS::readlink;
        open = &RepoVFS::open;
        read = &RepoVFS::read;
        opendir = &RepoVFS::opendir;
        readdir = &RepoVFS::readdir;
        releasedir = &RepoVFS::releasedir;
    }
};

const struct RepoVFS::FuseLLOps RepoVFS::fuse_ll_ops;

struct RepoVFS::Node {
    // Creates a new node. Make sure to set the node's stat.st_ino once inserted.
    Node(fuse_ino_t parentIno, const struct stat &stat) : parentIno(parentIno), stat(stat) { }

    virtual ~Node() { }

    // In the case of hardlinked files this might not be the entire truth.
    fuse_ino_t parentIno;
    struct stat stat;
};

struct RepoVFS::DirNode : public RepoVFS::Node {
    using Node::Node;
    // Map of filename -> children inode.
    // Use std::less<> to allow indexing with std::string_view
    std::map<std::string, fuse_ino_t, std::less<>> children;

    // Set to true if at least one package owns this.
    // This allows reading in RPMs in arbitrary order,
    // filling in missing directory metainfo when it arrives.
    bool packageOwned = false;
};

struct RepoVFS::FileNode : public RepoVFS::Node {
    using Node::Node;
    std::string pathOfPackage;
    rpm_ino_t inoInPackage;
};

struct RepoVFS::SymlinkNode : public RepoVFS::Node {
    using Node::Node;
    std::string target;
};

RepoVFS::DirNode *RepoVFS::makeDirNode(fuse_ino_t parent)
{
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

// clang-format off
RepoVFS::Node* RepoVFS::nodeForIno(fuse_ino_t ino)
{
    return ino >= nodes.size() ? nullptr : nodes[ino].get();
}
// clang-format on

RepoVFS::RepoVFS()
{
    rpmReadConfigFiles(NULL, NULL);
    ts = rpmtsCreate();

    // inode 0 is invalid
    nodes.push_back(nullptr);

    // inode 1 is the root. It has itself as parent.
    makeDirNode(1);
}

RepoVFS::~RepoVFS()
{
    if (fuseSession) {
        fuse_session_unmount(fuseSession);
        fuse_session_destroy(fuseSession);
        fuseSession = nullptr;
    }

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
    if (int rc = rpmReadPackageFile(ts, f, path.c_str(), &hdr); rc != RPMRC_OK) {
        rpmlog(RPMLOG_ERR, "%s: %d\n", path.c_str(), rc);
        return false;
    }
    auto hdrfree = Defer([&] { headerFree(hdr); });

    // Iterate all files
    rpmfi fi = rpmfiNew(ts, hdr, RPMTAG_BASENAMES, RPMFI_NOHEADER | RPMFI_FLAGS_QUERY);
    auto fifree = Defer([&] { rpmfiFree(fi); });

    // Data for handling hardlinks. Map package inodes to repomount inodes.
    std::map<rpm_ino_t, fuse_ino_t> inodeMap;

    fi = rpmfiInit(fi, 0);
    while (rpmfiNext(fi) >= 0) {
        // Ignore %ghost files
        if (rpmfiFFlags(fi) & RPMFILE_GHOST)
            continue;

        // This does quite a bit of work for us already,
        // even translating uid/gid with proper fallback.
        struct stat stat;
        if (rpmfiStat(fi, 0, &stat) != 0)
            return false;

        // fn="/usr/libexec/convertfs"
        const char *fn = rpmfiFN(fi);
        // dn="/usr/libexec/" bn="convertfs"
        const char *dn = rpmfiDN(fi), *bn = rpmfiBN(fi);

        // Traverse into the target directory
        auto *currentDirNode = dynamic_cast<DirNode *>(nodes[1].get());
        for (auto pathPart : std::ranges::split_view { std::string_view(dn), '/' }) {
            std::string_view component(pathPart.begin(), pathPart.end());
            // Skip empty components, such as the beginning and end of
            // "/usr/libexec/"
            if (component.empty())
                continue;

            auto thisNode = nodeByName(currentDirNode, component);
            if (!thisNode) {
                // Directory not found, create a placeholder
                thisNode = makeDirNode(currentDirNode->stat.st_ino);
                currentDirNode->children[std::string(component)] = thisNode->stat.st_ino;
                currentDirNode = dynamic_cast<DirNode *>(thisNode);
            } else if (auto dirNode = dynamic_cast<DirNode *>(thisNode)) {
                // Directory exists, use it
                currentDirNode = dirNode;
            } else {
                // Node exists, but isn't a directory
                rpmlog(RPMLOG_ERR, "Component %s of %s not a directory\n", std::string(component).c_str(), fn);
                return false;
            }
        }

        // Target directory reached, check whether the node exists already
        auto thisNode = nodeByName(currentDirNode, bn);
        if (thisNode) {
            // Node already exists, only allowed for directories
            if (!S_ISDIR(stat.st_mode) || !S_ISDIR(thisNode->stat.st_mode)) {
                rpmlog(RPMLOG_ERR, "%s has type mismatch\n", fn);
                return false;
            }

            auto dirNode = dynamic_cast<DirNode *>(thisNode);
            if (dirNode->packageOwned) {
                // Already owned, check for conflicts
                if (dirNode->stat.st_mode != stat.st_mode)
                    rpmlog(RPMLOG_WARNING, "Conflicting modes for dir %s\n", fn);
                if (dirNode->stat.st_uid != stat.st_uid || dirNode->stat.st_gid != stat.st_gid)
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
        if (S_ISDIR(stat.st_mode)) {
            nodes.push_back(std::make_unique<DirNode>(currentDirNode->stat.st_ino, stat));
            currentDirNode->children[bn] = stat.st_ino;
        } else if (S_ISREG(stat.st_mode)) {
            if (stat.st_nlink > 1) {
                // It's a hardlink. Does a node already exist?
                if (auto it = inodeMap.find(rpmfiFInode(fi)); it != inodeMap.end()) {
                    // Yes, use it.
                    currentDirNode->children[bn] = it->second;
                    continue;
                }
            }

            auto node = std::make_unique<FileNode>(currentDirNode->stat.st_ino, stat);
            node->pathOfPackage = path;
            node->inoInPackage = rpmfiFInode(fi);
            nodes.push_back(std::move(node));
            currentDirNode->children[bn] = stat.st_ino;

            // First hardlink created, add to map
            if (stat.st_nlink > 1)
                inodeMap[rpmfiFInode(fi)] = stat.st_ino;
        } else if (S_ISLNK(stat.st_mode)) {
            auto target = rpmfiFLink(fi);
            if (!target || target[0] == '/') {
                rpmlog(RPMLOG_WARNING, "Symlink %s -> %s unhandled\n", fn, target);
                continue;
            }

            auto node = std::make_unique<SymlinkNode>(currentDirNode->stat.st_ino, stat);
            node->target = target;
            nodes.push_back(std::move(node));
            currentDirNode->children[bn] = stat.st_ino;
        } else {
            rpmlog(RPMLOG_WARNING, "Mode %o not handled for file %s\n", stat.st_mode, fn);
        }
    }

    return true;
}

bool RepoVFS::mount(struct fuse_args &args, const std::string &path)
{
    fuseSession = fuse_session_new(&args, &fuse_ll_ops, sizeof(fuse_ll_ops), this);
    if (!fuseSession)
        return false;

    if (fuse_session_mount(fuseSession, path.c_str()) != 0)
        return false;

    fuse_set_signal_handlers(fuseSession);
    return true;
}

int RepoVFS::fuseFD()
{
    return fuse_session_fd(fuseSession);
}

bool RepoVFS::processFuseRequests()
{
    // Never deallocated, just reused
    static struct fuse_buf fbuf = {};

    // Read requests until empty (-EAGAIN) or error
    for(;;)
    {
        int res = fuse_session_receive_buf(fuseSession, &fbuf);

        if (res == -EINTR || res == -EAGAIN)
            break;

        if (res <= 0)
        {
            if(res < 0) // Error
                rpmlog(RPMLOG_ERR, "Error reading FUSE request: %s", strerror(errno));

            return false;
        }

        fuse_session_process_buf(fuseSession, &fbuf);
    }

    return true;
}

void RepoVFS::replyEntry(fuse_req_t req, RepoVFS::Node *node)
{
    // Zero means invalid entry. Compared to an ENOENT reply, the kernel can
    // cache this.
    struct fuse_entry_param entry { };

    if (node) {
        entry.ino = node->stat.st_ino;
        entry.attr_timeout = 60 * 60;
        entry.entry_timeout = 60 * 60;
        entry.attr = node->stat;
    }

    fuse_reply_entry(req, &entry);
}

void RepoVFS::lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    RepoVFS *that = reinterpret_cast<RepoVFS *>(fuse_req_userdata(req));
    auto parentNode = that->nodeForIno(parent);
    if (!parentNode) {
        fuse_reply_err(req, EIO);
        return;
    }

    auto parentDirNode = dynamic_cast<DirNode *>(parentNode);
    if (!parentDirNode) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }

    that->replyEntry(req, that->nodeByName(parentDirNode, name));
}

void RepoVFS::getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
    (void)fi;
    RepoVFS *that = reinterpret_cast<RepoVFS *>(fuse_req_userdata(req));
    auto node = that->nodeForIno(ino);
    if (!node) {
        fuse_reply_err(req, EIO);
        return;
    }

    fuse_reply_attr(req, &node->stat, 0);
}

void RepoVFS::readlink(fuse_req_t req, fuse_ino_t ino)
{
    RepoVFS *that = reinterpret_cast<RepoVFS *>(fuse_req_userdata(req));
    auto node = that->nodeForIno(ino);
    if (!node) {
        fuse_reply_err(req, EIO);
        return;
    }

    auto symlinkNode = dynamic_cast<SymlinkNode *>(node);
    if (!symlinkNode) {
        fuse_reply_err(req, EINVAL);
        return;
    }

    fuse_reply_readlink(req, symlinkNode->target.c_str());
}

static void appendDirentry(std::vector<char> &dirbuf, fuse_req_t req, const char *name, const struct stat *stbuf)
{
    size_t oldsize = dirbuf.size();
    dirbuf.resize(oldsize + fuse_add_direntry(req, nullptr, 0, name, nullptr, 0));
    fuse_add_direntry(req, dirbuf.data() + oldsize, dirbuf.size() + oldsize, name, stbuf, dirbuf.size());
}

void RepoVFS::opendir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
    RepoVFS *that = reinterpret_cast<RepoVFS *>(fuse_req_userdata(req));
    auto node = that->nodeForIno(ino);
    if (!node) {
        fuse_reply_err(req, EIO);
        return;
    }

    auto dirNode = dynamic_cast<DirNode *>(node);
    if (!dirNode) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }

    // Prepare the whole buffer now, store it in fi->fh.
    // readdir then just needs to reply with the requested slice.
    // Finally it's deleted by releasedir.
    auto dirbuf = std::make_unique<std::vector<char>>();
    appendDirentry(*dirbuf, req, ".", &node->stat);

    if (Node *parentNode = that->nodeForIno(node->parentIno); parentNode)
        appendDirentry(*dirbuf, req, "..", &parentNode->stat);

    for (auto ino : dirNode->children) {
        auto child = that->nodeForIno(ino.second);
        appendDirentry(*dirbuf, req, ino.first.c_str(), &child->stat);
    }

    fi->fh = reinterpret_cast<uint64_t>(dirbuf.release());
    fi->cache_readdir = true;
    fuse_reply_open(req, fi);
}

void RepoVFS::readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    (void)ino;
    std::vector<char> *dirbuf = reinterpret_cast<std::vector<char> *>(fi->fh);
    if (!dirbuf) {
        fuse_reply_err(req, EIO);
        return;
    }

    if (off < off_t(dirbuf->size()))
        fuse_reply_buf(req, dirbuf->data() + off, std::min(off_t(size), off_t(dirbuf->size()) - off));
    else
        fuse_reply_buf(req, nullptr, 0);
}

void RepoVFS::releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    (void)ino;
    delete reinterpret_cast<std::vector<char> *>(fi->fh);
    fuse_reply_err(req, 0);
}

void RepoVFS::open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
    (void)ino;
    fi->keep_cache = true;
    fuse_reply_open(req, fi);
}

void RepoVFS::read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *file_info)
{
    (void)file_info;
    RepoVFS *that = reinterpret_cast<RepoVFS *>(fuse_req_userdata(req));
    auto node = that->nodeForIno(ino);
    if (!node) {
        fuse_reply_err(req, EIO);
        return;
    }

    auto fileNode = dynamic_cast<FileNode *>(node);
    if (!fileNode) {
        fuse_reply_err(req, EINVAL);
        return;
    }

    // Reading past the end
    if (off >= off_t(fileNode->stat.st_size))
        size = 0;
    else
        size = std::min(off_t(fileNode->stat.st_size) - off, off_t(size));

    if (size == 0) {
        fuse_reply_buf(req, "", 0);
        return;
    }

    // Open the RPM file
    auto f = Fopen(fileNode->pathOfPackage.c_str(), "r.ufdio");
    if (Ferror(f)) {
        rpmlog(RPMLOG_ERR, "%s: %s\n", fileNode->pathOfPackage.c_str(), Fstrerror(f));
        fuse_reply_err(req, EIO);
        return;
    }
    auto ffree = Defer([&] { Fclose(f); });

    // Read the header
    Header hdr;
    if (int rc = rpmReadPackageFile(that->ts, f, fileNode->pathOfPackage.c_str(), &hdr); rc != RPMRC_OK) {
        rpmlog(RPMLOG_ERR, "%s: %d", fileNode->pathOfPackage.c_str(), rc);
        fuse_reply_err(req, EIO);
        return;
    }
    auto hdrfree = Defer([&] { headerFree(hdr); });

    const char *compr = headerGetString(hdr, RPMTAG_PAYLOADCOMPRESSOR);
    if (!compr)
        compr = "gzip";

    // Open the payload
    f = Fdopen(f, (std::string("r.") + compr).c_str());
    if (Ferror(f)) {
        rpmlog(RPMLOG_ERR, "Failed to reopen %s: %s", fileNode->pathOfPackage.c_str(), Fstrerror(f));
        fuse_reply_err(req, EIO);
        return;
    }

    rpmfiles files = rpmfilesNew(NULL, hdr, 0, RPMFI_KEEPHEADER);
    auto filesFree = Defer([&] { rpmfilesFree(files); });
    rpmfi fi = rpmfiNewArchiveReader(f, files, RPMFI_ITER_READ_ARCHIVE);
    auto fiFree = Defer([&] { rpmfiFree(fi); });

    // Iterate all files inside until the right one is found
    int rc = rpmfiNext(fi);
    for (; rc >= 0; rc = rpmfiNext(fi)) {
        if (rpmfiFInode(fi) != fileNode->inoInPackage || !rpmfiArchiveHasContent(fi))
            continue;

        // Seek to the right offset
        while (off > 0) {
            char buf[1024];
            size_t step = std::min(sizeof(buf), size_t(off));
            auto skipped = rpmfiArchiveRead(fi, buf, step);
            if (skipped <= 0) {
                fuse_reply_err(req, EIO);
                return;
            }

            off -= skipped;
        }

        // Read (exactly) the specified size
        std::vector<char> buf;
        buf.resize(size);
        char *ptr = buf.data();
        while (size > 0) {
            auto sizeRead = rpmfiArchiveRead(fi, ptr, size);
            if (sizeRead <= 0) {
                fuse_reply_err(req, EIO);
                return;
            }

            size -= sizeRead;
        }

        fuse_reply_buf(req, buf.data(), buf.size());
        return;
    }

    rpmlog(RPMLOG_ERR, "Content for inode %d not found in %s anymore\n", fileNode->inoInPackage,
        fileNode->pathOfPackage.c_str());
    fuse_reply_err(req, EIO);
}

RepoVFS::Node *RepoVFS::nodeByName(const DirNode *parentDir, const std::string_view &name)
{
    if (auto it = parentDir->children.find(name); it != parentDir->children.end())
        return nodes[it->second].get();

    return nullptr;
}

void RepoVFS::dumpTree(const DirNode *node, int level)
{
    for (auto child : node->children) {
        for (int i = 0; i < level; ++i)
            rpmlog(RPMLOG_NOTICE, "\t");

        auto childNode = nodes[child.second].get();
        if (auto dirChild = dynamic_cast<DirNode *>(childNode)) {
            rpmlog(RPMLOG_NOTICE, "%s\n", child.first.c_str());
            dumpTree(dirChild, level + 1);
        } else if (auto symlinkChild = dynamic_cast<SymlinkNode *>(childNode)) {
            rpmlog(RPMLOG_NOTICE, "%s -> %s\n", child.first.c_str(), symlinkChild->target.c_str());
        } else {
            rpmlog(RPMLOG_NOTICE, "%s\n", child.first.c_str());
        }
    }
}
