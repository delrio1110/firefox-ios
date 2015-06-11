/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import Foundation
import Shared
import XCGLogger

private let log = XCGLogger.defaultInstance()

let TableLoginsMirror = "loginsM"
let TableLoginsLocal = "loginsL"
let AllTables: Args = [TableLoginsMirror, TableLoginsLocal]

private class LoginsTable: Table {
    var name: String { return "LOGINS" }
    var version: Int { return 2 }

    func run(db: SQLiteDBConnection, sql: String, args: Args? = nil) -> Bool {
        let err = db.executeChange(sql, withArgs: args)
        if err != nil {
            log.error("Error running SQL in LoginsTable. \(err?.localizedDescription)")
            log.error("SQL was \(sql)")
        }
        return err == nil
    }

    // TODO: transaction.
    func run(db: SQLiteDBConnection, queries: [String]) -> Bool {
        for sql in queries {
            if !run(db, sql: sql, args: nil) {
                return false
            }
        }
        return true
    }

    func create(db: SQLiteDBConnection, version: Int) -> Bool {
        // We ignore the version.

        let common =
        "id INTEGER PRIMARY KEY AUTOINCREMENT" +
        ", hostname TEXT NOT NULL" +
        ", httpRealm TEXT" +
        ", formSubmitUrl TEXT" +
        ", usernameField TEXT" +
        ", passwordField TEXT" +
        ", timeCreated INTEGER NOT NULL" +
        ", timeLastUsed INTEGER" +
        ", timePasswordChanged INTEGER NOT NULL" +
        ", username TEXT" +
        ", password TEXT NOT NULL"

        let mirror = "CREATE TABLE IF NOT EXISTS \(TableLoginsMirror) (" +
            common +
            ", guid TEXT NOT NULL UNIQUE" +
            ", server_modified INTEGER NOT NULL" +              // Integer milliseconds.
            ", is_overridden TINYINT NOT NULL DEFAULT = 0" +
        ")"

        let local = "CREATE TABLE IF NOT EXISTS \(TableLoginsLocal) (" +
            common +
            ", guid TEXT UNIQUE REFERENCES \(TableLoginsMirror)(guid)" +       // Can be null if locally new.
            ", local_modified INTEGER" +          // Can be null. Client clock. In extremis only.
            ", is_deleted TINYINT NOT NULL" +     // Boolean. Locally deleted.
            ", should_upload TINYINT NOT NULL" +  // Boolean. Set when changed or created.
        ")"

        return self.run(db, queries: [mirror, local])
    }

    func updateTable(db: SQLiteDBConnection, from: Int, to: Int) -> Bool {
        if from == to {
            log.debug("Skipping update from \(from) to \(to).")
            return true
        }

        if from == 0 {
            // This is likely an upgrade from before Bug 1160399.
            log.debug("Updating logins tables from zero. Assuming drop and recreate.")
            return drop(db) && create(db, version: to)
        }

        // TODO: real update!
        log.debug("Updating logins table from \(from) to \(to).")
        return drop(db) && create(db, version: to)
    }

    func exists(db: SQLiteDBConnection) -> Bool {
        return db.tablesExist(AllTables)
    }

    func drop(db: SQLiteDBConnection) -> Bool {
        log.debug("Dropping logins table.")
        let err = db.executeChange("DROP TABLE IF EXISTS \(name)", withArgs: nil)
        return err == nil
    }

}

public class SQLiteLogins: BrowserLogins {
    private let table = LoginsTable()
    private let db: BrowserDB

    public init(db: BrowserDB) {
        self.db = db
        db.createOrUpdate(table)
    }

    private class func LoginFactory(row: SDRow) -> Login {
        let c = NSURLCredential(user: row["username"] as? String ?? "",
            password: row["password"] as! String,
            persistence: NSURLCredentialPersistence.None)
        let protectionSpace = NSURLProtectionSpace(host: row["hostname"] as! String,
            port: 0,
            `protocol`: nil,
            realm: row["httpRealm"] as? String,
            authenticationMethod: nil)

        let login = Login(credential: c, protectionSpace: protectionSpace)
        login.formSubmitUrl = row["formSubmitUrl"] as? String
        login.usernameField = row["usernameField"] as? String
        login.passwordField = row["passwordField"] as? String

        if let timeCreated = row.getTimestamp("timeCreated"),
            let timeLastUsed = row.getTimestamp("timeLastUsed"),
            let timePasswordChanged = row.getTimestamp("timePasswordChanged") {
                login.timeCreated = timeCreated
                login.timeLastUsed = timeLastUsed
                login.timePasswordChanged = timePasswordChanged
        }

        return login
    }

    private class func LoginDataFactory(row: SDRow) -> LoginData {
        return LoginFactory(row) as LoginData
    }

    private class func LoginUsageDataFactory(row: SDRow) -> LoginUsageData {
        return LoginFactory(row) as LoginUsageData
    }

    public func getLoginsForProtectionSpace(protectionSpace: NSURLProtectionSpace) -> Deferred<Result<Cursor<LoginData>>> {
        let sql = "SELECT username, password, hostname, httpRealm, formSubmitUrl, usernameField, passwordField FROM \(table.name) WHERE hostname = ? ORDER BY timeLastUsed DESC"
        let args: [AnyObject?] = [protectionSpace.host]
        return db.runQuery(sql, args: args, factory: SQLiteLogins.LoginDataFactory)
    }

    public func getUsageDataForLogin(login: LoginData) -> Deferred<Result<LoginUsageData>> {
        let sql = "SELECT * FROM \(table.name) WHERE hostname = ? AND username IS ? LIMIT 1"
        let args: [AnyObject?] = [login.hostname, login.username]
        return db.runQuery(sql, args: args, factory: SQLiteLogins.LoginUsageDataFactory) >>== { value in
            return deferResult(value[0]!)
        }
    }

    public func addLogin(login: LoginData) -> Success {
        var args = [AnyObject?]()
        args.append(login.hostname)
        args.append(login.httpRealm)
        args.append(login.formSubmitUrl)
        args.append(login.usernameField)
        args.append(login.passwordField)

        if var login = login as? SyncableLoginData {
            if login.guid == nil {
                login.guid = Bytes.generateGUID()
            }
            args.append(login.guid)
        } else {
            args.append(Bytes.generateGUID())
        }

        let date = NSNumber(unsignedLongLong: NSDate.nowMicroseconds())
        args.append(date) // timeCreated
        args.append(date) // timeLastUsed
        args.append(date) // timePasswordChanged
        args.append(login.username)
        args.append(login.password)

        return db.run("INSERT INTO \(table.name) (hostname, httpRealm, formSubmitUrl, usernameField, passwordField, guid, timeCreated, timeLastUsed, timePasswordChanged, username, password) VALUES (?,?,?,?,?,?,?,?,?,?,?)", withArgs: args)
    }

    public func addUseOf(login: LoginData) -> Success {
        let date = NSNumber(unsignedLongLong: NSDate.nowMicroseconds())
        return db.run("UPDATE \(table.name) SET timeLastUsed = ? WHERE hostname = ? AND username IS ?", withArgs: [date, login.hostname, login.username])
    }

    public func updateLogin(login: LoginData) -> Success {
        let date = NSNumber(unsignedLongLong: NSDate.nowMicroseconds())
        var args: Args = [
            login.httpRealm,
            login.formSubmitUrl,
            login.usernameField,
            login.passwordField,
            date, // timePasswordChanged
            login.password,
            login.hostname,
            login.username]

        return db.run("UPDATE \(table.name) SET httpRealm = ?, formSubmitUrl = ?, usernameField = ?, passwordField = ?, timePasswordChanged = ?, password = ? WHERE hostname = ? AND username IS ?", withArgs: args)
    }

    public func removeLogin(login: LoginData) -> Success {
        var args: Args = [login.hostname, login.username]
        return db.run("DELETE FROM \(table.name) WHERE hostname = ? AND username IS ?", withArgs: args)
    }

    public func removeAll() -> Success {
        return db.run("DELETE FROM \(table.name)")
    }
}
