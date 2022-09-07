/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2022 Fabian Vogt <fabian@suse.de>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#pragma once

#include <fuse_lowlevel.h>
#include <rpm/rpmts.h>
#include <memory>
#include <vector>
#include <string_view>

class RepoVFS
{
   struct Node;
   struct DirNode;
   struct FileNode;
   struct SymlinkNode;

public:
   RepoVFS();
   ~RepoVFS();
   bool addRPM(const std::string &path);
   bool mountAndLoop(const std::string &path);

private:
   DirNode* makeDirNode(fuse_ino_t parent);
   Node *nodeByName(const DirNode *parent, const std::string_view &name);
   void dumpTree(const DirNode *node, int level = 0);

   std::vector<std::unique_ptr<Node>> nodes;
   rpmts ts = rpmtsCreate();
};
