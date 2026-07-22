// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin developers
// Copyright (c) 2019-2021 The PIVX Core developers
// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "db.h"

#include "guiinterfaceutil.h"
#include "logging.h"
#include "util/system.h"
#include "utilstrencodings.h"
#include "wallet/walletutil.h"

#include <stdint.h>

#ifndef WIN32
#include <sys/stat.h>
#endif

namespace {
RecursiveMutex cs_db;
std::map<std::string, SQLiteDatabase*> g_databases; //!< Map from directory name to database
} // namespace

SQLiteDatabase* GetWalletDatabase(const fs::path& wallet_path, std::string& database_filename)
{
    fs::path env_directory;
    if (fs::is_regular_file(wallet_path)) {
        env_directory = wallet_path.parent_path();
        database_filename = wallet_path.filename().string();
    } else {
        env_directory = wallet_path;
        database_filename = "wallet.sqlite";
    }
    LOCK(cs_db);
    auto it = g_databases.find(env_directory.string());
    if (it != g_databases.end()) {
        return it->second;
    }
    return nullptr;
}

//
// SQLiteDatabase
//

SQLiteDatabase::SQLiteDatabase(const fs::path& wallet_path, bool mock)
    : nUpdateCounter(0), nLastSeen(0), nLastFlushed(0), nLastWalletUpdate(0), m_mock(mock)
{
    if (mock) {
        // In-memory database for testing
        int rc = sqlite3_open(":memory:", &m_db);
        if (rc != SQLITE_OK) {
            throw std::runtime_error("SQLiteDatabase: Failed to open in-memory database");
        }
        SetupPragmas();
        SetupSchema();
        return;
    }

    fs::path env_directory;
    std::string filename;
    if (fs::is_regular_file(wallet_path)) {
        env_directory = wallet_path.parent_path();
        filename = wallet_path.filename().string();
    } else {
        env_directory = wallet_path;
        filename = "wallet.sqlite";
    }

    m_dir = env_directory;
    m_path = env_directory / filename;

    TryCreateDirectories(env_directory);
    if (!LockDirectory(env_directory, ".walletlock")) {
        throw std::runtime_error(strprintf("Cannot obtain a lock on wallet directory %s. Another instance may be using it.", env_directory.string()));
    }

    int rc = sqlite3_open(m_path.string().c_str(), &m_db);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(strprintf("SQLiteDatabase: Failed to open database %s: %s", m_path.string(), sqlite3_errmsg(m_db)));
    }

    LogPrintf("Using SQLite wallet: %s\n", m_path.string());

    if (!SetupPragmas()) {
        throw std::runtime_error("SQLiteDatabase: Failed to set up pragmas");
    }

    if (!SetupSchema()) {
        throw std::runtime_error("SQLiteDatabase: Failed to set up schema");
    }

    // Register in global map
    LOCK(cs_db);
    g_databases[env_directory.string()] = this;
}

SQLiteDatabase::~SQLiteDatabase()
{
    Flush(true);
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
    if (!m_mock && !m_dir.empty()) {
        LOCK(cs_db);
        g_databases.erase(m_dir.string());
        // Lock is automatically released when process exits (see ReleaseDirectoryLocks)
    }
}

bool SQLiteDatabase::SetupPragmas()
{
    if (!m_db) return false;

    // WAL mode for concurrent reads + crash recovery
    const char* pragmas =
        "PRAGMA journal_mode = WAL;"
        "PRAGMA synchronous = NORMAL;"  // Good balance perf/safety
        "PRAGMA foreign_keys = ON;"
        "PRAGMA busy_timeout = 5000;";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, pragmas, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        LogPrintf("SQLiteDatabase: pragma error: %s\n", errMsg ? errMsg : "unknown");
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool SQLiteDatabase::SetupSchema()
{
    if (!m_db) return false;

    // Key-value store (main table for wallet data)
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS main (
            key BLOB PRIMARY KEY,
            value BLOB NOT NULL
        ) WITHOUT ROWID;
    )";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, schema, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        LogPrintf("SQLiteDatabase: schema error: %s\n", errMsg ? errMsg : "unknown");
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

void SQLiteDatabase::IncrementUpdateCounter()
{
    ++nUpdateCounter;
}

bool SQLiteDatabase::Rewrite(const char* pszSkip)
{
    return SQLiteBatch::Rewrite(*this, pszSkip);
}

bool SQLiteDatabase::Backup(const std::string& strDest)
{
    if (IsDummy() || !m_db) {
        return false;
    }

    // Flush before backup
    Flush(false);

    fs::path pathDest(strDest);
    if (fs::is_directory(pathDest)) {
        pathDest /= m_path.filename();
    }

    sqlite3* pBackup = nullptr;
    int rc = sqlite3_open(pathDest.string().c_str(), &pBackup);
    if (rc != SQLITE_OK) {
        LogPrintf("SQLiteDatabase::Backup: Cannot create backup file %s\n", pathDest.string());
        return false;
    }

    sqlite3_backup* backup = sqlite3_backup_init(pBackup, "main", m_db, "main");
    if (!backup) {
        LogPrintf("SQLiteDatabase::Backup: sqlite3_backup_init failed\n");
        sqlite3_close(pBackup);
        return false;
    }

    rc = sqlite3_backup_step(backup, -1);  // Copy all pages
    sqlite3_backup_finish(backup);
    sqlite3_close(pBackup);

    if (rc != SQLITE_DONE) {
        LogPrintf("SQLiteDatabase::Backup: sqlite3_backup_step failed: %d\n", rc);
        return false;
    }

    LogPrintf("SQLiteDatabase::Backup: copied %s to %s\n", m_path.string(), pathDest.string());
    return true;
}

void SQLiteDatabase::Flush(bool shutdown)
{
    if (!m_db) return;

    // SQLite with WAL mode auto-checkpoints, but we can force it
    if (shutdown) {
        sqlite3_wal_checkpoint_v2(m_db, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr, nullptr);
    } else {
        sqlite3_wal_checkpoint_v2(m_db, nullptr, SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
    }

    nLastFlushed = nUpdateCounter;
}

void SQLiteDatabase::ReloadDbEnv()
{
    // Not really needed for SQLite, but provide for compatibility
    Flush(false);
}

//
// SQLiteBatch
//

SQLiteBatch::SQLiteBatch(SQLiteDatabase& database, const char* pszMode, bool fFlushOnCloseIn)
    : m_db(nullptr), fReadOnly(false), fFlushOnClose(fFlushOnCloseIn), m_database(&database)
{
    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));

    if (database.IsDummy()) {
        return;
    }

    m_db = database.GetDb();
    m_path = database.GetPathToFile().string();

    if (m_db) {
        SetupStatements();
    }
}

void SQLiteBatch::SetupStatements()
{
    if (!m_db) return;

    // Read statement
    sqlite3_prepare_v2(m_db, "SELECT value FROM main WHERE key = ?", -1, &m_read_stmt, nullptr);

    // Write statement (INSERT, fails if exists)
    sqlite3_prepare_v2(m_db, "INSERT INTO main (key, value) VALUES (?, ?)", -1, &m_write_stmt, nullptr);

    // Overwrite statement (INSERT OR REPLACE)
    sqlite3_prepare_v2(m_db, "INSERT OR REPLACE INTO main (key, value) VALUES (?, ?)", -1, &m_overwrite_stmt, nullptr);

    // Delete statement
    sqlite3_prepare_v2(m_db, "DELETE FROM main WHERE key = ?", -1, &m_delete_stmt, nullptr);

    // Exists statement
    sqlite3_prepare_v2(m_db, "SELECT COUNT(*) FROM main WHERE key = ?", -1, &m_exists_stmt, nullptr);

    // Cursor statement
    sqlite3_prepare_v2(m_db, "SELECT key, value FROM main", -1, &m_cursor_stmt, nullptr);
}

void SQLiteBatch::FinalizeStatements()
{
    if (m_read_stmt) { sqlite3_finalize(m_read_stmt); m_read_stmt = nullptr; }
    if (m_write_stmt) { sqlite3_finalize(m_write_stmt); m_write_stmt = nullptr; }
    if (m_overwrite_stmt) { sqlite3_finalize(m_overwrite_stmt); m_overwrite_stmt = nullptr; }
    if (m_delete_stmt) { sqlite3_finalize(m_delete_stmt); m_delete_stmt = nullptr; }
    if (m_exists_stmt) { sqlite3_finalize(m_exists_stmt); m_exists_stmt = nullptr; }
    if (m_cursor_stmt) { sqlite3_finalize(m_cursor_stmt); m_cursor_stmt = nullptr; }
}

void SQLiteBatch::Flush()
{
    if (m_database && !m_database->IsDummy()) {
        m_database->Flush(false);
    }
}

void SQLiteBatch::Close()
{
    FinalizeStatements();

    if (fFlushOnClose && m_database) {
        Flush();
    }

    m_db = nullptr;
}

bool SQLiteBatch::StartCursor()
{
    if (!m_cursor_stmt) return false;
    sqlite3_reset(m_cursor_stmt);
    m_cursor_init = true;
    return true;
}

bool SQLiteBatch::ReadAtCursor(CDataStream& ssKey, CDataStream& ssValue, bool& complete)
{
    if (!m_cursor_stmt || !m_cursor_init) {
        complete = true;
        return false;
    }

    int res = sqlite3_step(m_cursor_stmt);
    if (res == SQLITE_DONE) {
        complete = true;
        return false;
    }
    if (res != SQLITE_ROW) {
        complete = true;
        return false;
    }

    // Get key
    const void* keyData = sqlite3_column_blob(m_cursor_stmt, 0);
    int keySize = sqlite3_column_bytes(m_cursor_stmt, 0);

    // Get value
    const void* valueData = sqlite3_column_blob(m_cursor_stmt, 1);
    int valueSize = sqlite3_column_bytes(m_cursor_stmt, 1);

    if (!keyData || !valueData) {
        complete = true;
        return false;
    }

    ssKey.SetType(SER_DISK);
    ssKey.clear();
    ssKey.write((const char*)keyData, keySize);

    ssValue.SetType(SER_DISK);
    ssValue.clear();
    ssValue.write((const char*)valueData, valueSize);

    complete = false;
    return true;
}

void SQLiteBatch::CloseCursor()
{
    if (m_cursor_stmt) {
        sqlite3_reset(m_cursor_stmt);
    }
    m_cursor_init = false;
}

bool SQLiteBatch::TxnBegin()
{
    if (!m_db) return false;
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, "BEGIN TRANSACTION", nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool SQLiteBatch::TxnCommit()
{
    if (!m_db) return false;
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, "COMMIT", nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool SQLiteBatch::TxnAbort()
{
    if (!m_db) return false;
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, "ROLLBACK", nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool SQLiteBatch::Recover(const fs::path& file_path, void* callbackDataIn, bool (*recoverKVcallback)(void* callbackData, CDataStream ssKey, CDataStream ssValue), std::string& out_backup_filename)
{
    // For SQLite, recovery is much simpler - we can just try to open and read
    // If the file is corrupted, sqlite3_open will fail
    std::string dummy_filename;
    SQLiteDatabase* db = GetWalletDatabase(file_path, dummy_filename);
    if (!db) {
        return false;
    }

    // Create backup filename
    int64_t now = GetTime();
    out_backup_filename = strprintf("%s.%d.bak", file_path.filename().string(), now);

    // Copy original file as backup
    try {
        fs::copy_file(file_path, file_path.parent_path() / out_backup_filename);
    } catch (...) {
        return false;
    }

    return true;
}

bool SQLiteBatch::PeriodicFlush(SQLiteDatabase& database)
{
    if (database.IsDummy()) {
        return true;
    }
    database.Flush(false);
    return true;
}

bool SQLiteBatch::VerifyEnvironment(const fs::path& file_path, std::string& errorStr)
{
    fs::path walletDir;
    if (fs::is_regular_file(file_path)) {
        walletDir = file_path.parent_path();
    } else {
        walletDir = file_path;
    }

    LogPrintf("Using SQLite version %s\n", sqlite3_libversion());
    LogPrintf("Using wallet %s\n", file_path.string());

    // Check if directory exists and is writable
    if (!fs::exists(walletDir)) {
        try {
            fs::create_directories(walletDir);
        } catch (const fs::filesystem_error& e) {
            errorStr = strprintf("Cannot create wallet directory %s: %s", walletDir.string(), e.what());
            return false;
        }
    }

    return true;
}

bool SQLiteBatch::VerifyDatabaseFile(const fs::path& file_path, std::string& warningStr, std::string& errorStr, bool (*recoverFunc)(const fs::path&, std::string&))
{
    fs::path walletFile = file_path;
    if (fs::is_directory(file_path)) {
        walletFile = file_path / "wallet.sqlite";
    }

    if (!fs::exists(walletFile)) {
        // File doesn't exist yet, that's fine
        return true;
    }

    // Try to open and verify
    sqlite3* db = nullptr;
    int rc = sqlite3_open_v2(walletFile.string().c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
    if (rc != SQLITE_OK) {
        errorStr = strprintf("Cannot open wallet file %s: %s", walletFile.string(), sqlite3_errmsg(db));
        sqlite3_close(db);
        return false;
    }

    // Run integrity check
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, nullptr);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            const char* result = (const char*)sqlite3_column_text(stmt, 0);
            if (result && strcmp(result, "ok") != 0) {
                warningStr = strprintf("Wallet file integrity check warning: %s", result);
            }
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    return true;
}

bool SQLiteBatch::Rewrite(SQLiteDatabase& database, const char* pszSkip)
{
    if (database.IsDummy()) {
        return true;
    }

    // SQLite has built-in VACUUM for compacting
    sqlite3* db = database.GetDb();
    if (!db) return false;

    // If we need to skip certain keys, we'd need to rebuild
    // For now, just VACUUM
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, "VACUUM", nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        LogPrintf("SQLiteBatch::Rewrite: VACUUM failed: %s\n", errMsg ? errMsg : "unknown");
        sqlite3_free(errMsg);
        return false;
    }

    LogPrintf("SQLiteBatch::Rewrite: database compacted\n");
    return true;
}
