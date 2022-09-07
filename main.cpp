/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2022 Fabian Vogt <fabian@suse.de>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <string>

#include "repovfs.h"

int main(int argc, char *argv[])
{
    RepoVFS vfs;
    return vfs.addRPM(argv[1]) ? 0 : 1;
}
