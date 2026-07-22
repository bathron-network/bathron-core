// Copyright (c) 2019-2021 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addressbook.h"

namespace AddressBook {

    namespace AddressBookPurpose {
        const std::string UNKNOWN{"unknown"};
        const std::string RECEIVE{"receive"};
        const std::string SEND{"send"};
        const std::string SHIELDED_RECEIVE{"shielded_receive"};
        const std::string SHIELDED_SEND{"shielded_spend"};
    }

    bool IsShieldedPurpose(const std::string& purpose) {
        return purpose == AddressBookPurpose::SHIELDED_RECEIVE
               || purpose == AddressBookPurpose::SHIELDED_SEND;
    }

    bool CAddressBookData::isShielded() const {
        return IsShieldedPurpose(purpose);
    }


}

