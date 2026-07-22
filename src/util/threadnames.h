// Copyright (c) 2018-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_UTIL_THREADNAMES_H
#define BATHRON_UTIL_THREADNAMES_H

#include <string>

namespace util {
//! Rename a thread both in terms of an internal (in-memory) name as well
//! as its system thread name.
//! @note Do not call this for the main thread, as this will interfere with
//! UNIX utilities such as top and killall.
void ThreadRename(std::string&&);

//! Get the thread's internal (in-memory) name; used e.g. for identification in
//! logging.
const std::string& ThreadGetInternalName();

} // namespace util

#endif // BATHRON_UTIL_THREADNAMES_H
