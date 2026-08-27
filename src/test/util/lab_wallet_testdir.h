// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// LAB-WALLET-TEST-ISOLATION-1
//
// Isolation fail-closed du répertoire wallet pour les tests qui ouvrent une base sur
// disque.
//
// Problème corrigé : un test qui appelle GetWalletDir() sans avoir redirigé -datadir
// retombe sur GetDataDir(), c'est-à-dire le datadir de PRODUCTION réel
// (~/Library/Application Support/BATHRON sur macOS, ~/.bathron ailleurs). Il y crée des
// wallets, les laisse en place, et n'est donc pas idempotent : la seconde exécution
// retrouve son propre résidu et échoue.
//
// Aggravant : l'isolation apparente de wallet_zkeys_tests ne tenait qu'à un effet de
// bord. La fixture TestingSetup du PREMIER cas de la suite appelle SetDataDir puis
// ClearDatadirCache ; gArgs.ForceSetArg étant global au processus, le second cas héritait
// silencieusement de cette redirection. Exécuté seul, il écrivait en production.
//
// Ce helper rend la redirection explicite et vérifiée, pour chaque cas qui en a besoin.
//
// Le nettoyage est déjà assuré par ~BasicTestingSetup, qui fait fs::remove_all(m_path_root)
// sur SA racine temporaire et sur elle seule. Ce fichier n'efface donc rien lui-même.

#ifndef BATHRON_TEST_UTIL_LAB_WALLET_TESTDIR_H
#define BATHRON_TEST_UTIL_LAB_WALLET_TESTDIR_H

#include "fs.h"
#include "util/system.h"
#include "wallet/walletutil.h"

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <string>
#include <vector>

namespace lab_test {

//! Datadirs persistants connus. Un test ne doit jamais écrire dessous.
inline std::vector<fs::path> KnownPersistentDataDirs()
{
    std::vector<fs::path> dirs;
    const char* home = std::getenv("HOME");
    if (home != nullptr && *home != '\0') {
        const fs::path h(home);
        dirs.push_back(h / ".bathron");                                   // Unix
        dirs.push_back(h / "Library" / "Application Support" / "BATHRON"); // macOS
    }
    return dirs;
}

//! Vrai si `p` est `base` ou se trouve strictement dessous. Comparaison composant par
//! composant : évite qu'un simple préfixe de chaîne (".../BATHRONParams") produise une
//! correspondance sur ".../BATHRON".
inline bool PathIsWithin(const fs::path& p, const fs::path& base)
{
    if (base.empty()) return false;
    auto ip = p.begin();
    auto ib = base.begin();
    for (; ib != base.end(); ++ib, ++ip) {
        if (ip == p.end()) return false;
        if (*ip != *ib) return false;
    }
    return true;
}

//! Garde FAIL-CLOSED. Interrompt le test au moindre doute.
//!
//! Refuse : une racine vide, un chemin vide, un chemin hors de `root`, un chemin égal à
//! HOME ou à "/", et tout chemin sous un datadir persistant connu.
inline void RequireIsolatedWalletPath(const fs::path& dir, const fs::path& root)
{
    BOOST_REQUIRE_MESSAGE(!root.empty(), "racine temporaire vide — refus");
    BOOST_REQUIRE_MESSAGE(!dir.empty(), "chemin wallet vide — refus");

    const fs::path abs_dir = fs::absolute(dir);
    const fs::path abs_root = fs::absolute(root);

    BOOST_REQUIRE_MESSAGE(abs_root != fs::path("/"), "racine temporaire = / — refus");
    BOOST_REQUIRE_MESSAGE(abs_dir != fs::path("/"), "chemin wallet = / — refus");

    const char* home = std::getenv("HOME");
    if (home != nullptr && *home != '\0') {
        const fs::path h = fs::absolute(fs::path(home));
        BOOST_REQUIRE_MESSAGE(abs_dir != h, "chemin wallet = HOME — refus");
        BOOST_REQUIRE_MESSAGE(abs_root != h, "racine temporaire = HOME — refus");
    }

    BOOST_REQUIRE_MESSAGE(PathIsWithin(abs_dir, abs_root),
                          "chemin wallet hors de la racine temporaire — refus : "
                              + abs_dir.string() + " (racine " + abs_root.string() + ")");

    for (const fs::path& prod : KnownPersistentDataDirs()) {
        const fs::path abs_prod = fs::absolute(prod);
        BOOST_REQUIRE_MESSAGE(!PathIsWithin(abs_dir, abs_prod),
                              "chemin wallet sous un datadir persistant — refus : "
                                  + abs_dir.string() + " (datadir " + abs_prod.string() + ")");
        BOOST_REQUIRE_MESSAGE(!PathIsWithin(abs_root, abs_prod),
                              "racine temporaire sous un datadir persistant — refus : "
                                  + abs_root.string());
    }
}

//! Redirige le datadir du processus vers une racine temporaire propre au cas de test,
//! puis renvoie le répertoire wallet isolé, vérifié.
//!
//! `fixture` doit exposer SetDataDir (BasicTestingSetup et ses dérivés). `name` doit être
//! unique par cas de test ; la racine renvoyée par SetDataDir est déjà unique par
//! exécution, m_path_root contenant une composante aléatoire.
//!
//! L'ORDRE compte : SetDataDir positionne -datadir mais ne purge délibérément pas le
//! cache (voir la note dans test_bathron.cpp) ; sans ClearDatadirCache() juste après,
//! GetDataDir() continuerait de renvoyer la valeur déjà résolue, c'est-à-dire le datadir
//! de production.
template <typename Fixture>
fs::path SetupIsolatedWalletDir(Fixture& fixture, const std::string& name)
{
    const fs::path root = fixture.SetDataDir(name);
    ClearDatadirCache();

    const fs::path wallet_dir = GetWalletDir();
    RequireIsolatedWalletPath(wallet_dir, root);
    return wallet_dir;
}

} // namespace lab_test

#endif // BATHRON_TEST_UTIL_LAB_WALLET_TESTDIR_H
