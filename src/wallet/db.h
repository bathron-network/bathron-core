// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin developers
// Copyright (c) 2019-2021 The PIVX Core developers
// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_WALLET_DB_H
#define BATHRON_WALLET_DB_H

#include "clientversion.h"
#include "fs.h"
#include "serialize.h"
#include "streams.h"
#include "sync.h"

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <sqlite3.h>

class SQLiteDatabase;
class SQLiteBatch;

/** Get database and filename given a wallet path. */
SQLiteDatabase* GetWalletDatabase(const fs::path& wallet_path, std::string& database_filename);

/**
 * An instance of this class represents one SQLite database.
 */
class SQLiteDatabase
{
    friend class SQLiteBatch;
public:
    /** Create dummy DB handle */
    SQLiteDatabase() : nUpdateCounter(0), nLastSeen(0), nLastFlushed(0), nLastWalletUpdate(0)
    {
    }

    /** Create DB handle to real database */
    explicit SQLiteDatabase(const fs::path& wallet_path, bool mock = false);

    ~SQLiteDatabase();

    /** Return object for accessing database at specified path. */
    static std::unique_ptr<SQLiteDatabase> Create(const fs::path& path)
    {
        return std::make_unique<SQLiteDatabase>(path);
    }

    /** Return object for accessing dummy database with no read/write capabilities. */
    static std::unique_ptr<SQLiteDatabase> CreateDummy()
    {
        return std::make_unique<SQLiteDatabase>();
    }

    /** Return object for accessing temporary in-memory database. */
    static std::unique_ptr<SQLiteDatabase> CreateMock()
    {
        return std::make_unique<SQLiteDatabase>("", true /* mock */);
    }

    /** Rewrite the entire database on disk, with the exception of key pszSkip if non-zero */
    bool Rewrite(const char* pszSkip = nullptr);

    /** Back up the entire database to a file. */
    bool Backup(const std::string& strDest);

    /** Make sure all changes are flushed to disk. */
    void Flush(bool shutdown);

    void IncrementUpdateCounter();

    void ReloadDbEnv();

    std::atomic<unsigned int> nUpdateCounter;
    unsigned int nLastSeen;
    unsigned int nLastFlushed;
    int64_t nLastWalletUpdate;

    fs::path GetPathToFile() { return m_path; }

    /** Return whether this database handle is a dummy for testing. */
    bool IsDummy() const { return m_db == nullptr && m_path.empty(); }

    sqlite3* GetDb() { return m_db; }
    const fs::path& Directory() const { return m_dir; }

private:
    // Note: Declaration order matters for initialization
    sqlite3* m_db{nullptr};
    fs::path m_path;
    fs::path m_dir;
    bool m_mock{false};

    bool SetupSchema();
    bool SetupPragmas();
};

/** RAII class that provides access to a SQLite database */
class SQLiteBatch
{
protected:
    sqlite3* m_db;
    std::string m_path;
    bool fReadOnly;
    bool fFlushOnClose;
    SQLiteDatabase* m_database;

    // Prepared statements for key-value operations
    sqlite3_stmt* m_read_stmt{nullptr};
    sqlite3_stmt* m_write_stmt{nullptr};
    sqlite3_stmt* m_overwrite_stmt{nullptr};
    sqlite3_stmt* m_delete_stmt{nullptr};
    sqlite3_stmt* m_exists_stmt{nullptr};
    sqlite3_stmt* m_cursor_stmt{nullptr};

    void SetupStatements();
    void FinalizeStatements();

public:
    explicit SQLiteBatch(SQLiteDatabase& database, const char* pszMode = "r+", bool fFlushOnCloseIn = true);
    ~SQLiteBatch() { Close(); }

    SQLiteBatch(const SQLiteBatch&) = delete;
    SQLiteBatch& operator=(const SQLiteBatch&) = delete;

    void Flush();
    void Close();

    static bool Recover(const fs::path& file_path, void* callbackDataIn, bool (*recoverKVcallback)(void* callbackData, CDataStream ssKey, CDataStream ssValue), std::string& out_backup_filename);

    /* flush the wallet passively (TRY_LOCK)
       ideal to be called periodically */
    static bool PeriodicFlush(SQLiteDatabase& database);
    /* verifies the database environment */
    static bool VerifyEnvironment(const fs::path& file_path, std::string& errorStr);
    /* verifies the database file */
    static bool VerifyDatabaseFile(const fs::path& file_path, std::string& warningStr, std::string& errorStr, bool (*recoverFunc)(const fs::path&, std::string&) = nullptr);

public:
    template <typename K, typename T>
    bool Read(const K& key, T& value)
    {
        if (!m_db)
            return false;

        // Serialize key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;

        // Bind key and execute
        sqlite3_reset(m_read_stmt);
        sqlite3_bind_blob(m_read_stmt, 1, ssKey.data(), ssKey.size(), SQLITE_STATIC);

        int res = sqlite3_step(m_read_stmt);
        if (res != SQLITE_ROW) {
            return false;
        }

        // Get value
        const void* data = sqlite3_column_blob(m_read_stmt, 0);
        int size = sqlite3_column_bytes(m_read_stmt, 0);
        if (!data || size == 0) {
            return false;
        }

        try {
            CDataStream ssValue((const char*)data, (const char*)data + size, SER_DISK, CLIENT_VERSION);
            ssValue >> value;
        } catch (const std::exception&) {
            return false;
        }

        return true;
    }

    template <typename K, typename T>
    bool Write(const K& key, const T& value, bool fOverwrite = true)
    {
        if (!m_db)
            return true;
        if (fReadOnly) {
            assert(!"Write called on database in read-only mode");
        }

        // Serialize key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;

        // Serialize value
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.reserve(10000);
        ssValue << value;

        sqlite3_stmt* stmt = fOverwrite ? m_overwrite_stmt : m_write_stmt;
        sqlite3_reset(stmt);
        sqlite3_bind_blob(stmt, 1, ssKey.data(), ssKey.size(), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, ssValue.data(), ssValue.size(), SQLITE_STATIC);

        int res = sqlite3_step(stmt);
        return res == SQLITE_DONE;
    }

    template <typename K>
    bool Erase(const K& key)
    {
        if (!m_db)
            return false;
        if (fReadOnly) {
            assert(!"Erase called on database in read-only mode");
        }

        // Serialize key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;

        sqlite3_reset(m_delete_stmt);
        sqlite3_bind_blob(m_delete_stmt, 1, ssKey.data(), ssKey.size(), SQLITE_STATIC);

        int res = sqlite3_step(m_delete_stmt);
        return res == SQLITE_DONE;
    }

    template <typename K>
    bool Exists(const K& key)
    {
        if (!m_db)
            return false;

        // Serialize key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;

        sqlite3_reset(m_exists_stmt);
        sqlite3_bind_blob(m_exists_stmt, 1, ssKey.data(), ssKey.size(), SQLITE_STATIC);

        int res = sqlite3_step(m_exists_stmt);
        if (res != SQLITE_ROW) {
            return false;
        }

        return sqlite3_column_int(m_exists_stmt, 0) > 0;
    }

    // Cursor operations for iterating over all keys
    bool StartCursor();
    bool ReadAtCursor(CDataStream& ssKey, CDataStream& ssValue, bool& complete);
    void CloseCursor();

public:
    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();

    bool WriteVersion(int nVersion)
    {
        return Write(std::string("version"), nVersion);
    }

    static bool Rewrite(SQLiteDatabase& database, const char* pszSkip = nullptr);

private:
    bool m_cursor_init{false};
};

// BATHRON: No Berkeley DB compatibility aliases
// This is a genesis chain - SQLite is the only wallet database
// All legacy BerkeleyXxx references have been cleaned up

#endif // BATHRON_WALLET_DB_H
