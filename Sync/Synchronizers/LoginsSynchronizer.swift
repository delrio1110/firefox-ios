/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import Foundation
import Shared
import Storage
import XCGLogger

private let log = XCGLogger.defaultInstance()
private let PasswordsStorageVersion = 1

// TODO: move to Logins.swift when Wes is done refactoring.
public protocol SyncableLogins {
    /**
     * Delete the login with the provided GUID. Succeeds if the GUID is unknown.
     */
    func deleteByGUID(guid: GUID, deletedAt: Timestamp) -> Success

    /**
     * Chains through the provided timestamp.
     */
    func markAsSynchronized([GUID], modified: Timestamp) -> Deferred<Result<Timestamp>>
    func markAsDeleted(guids: [GUID]) -> Success

    /**
     * Clean up any metadata.
     */
    func onRemovedAccount() -> Success
}

private func makeDeletedLoginRecord(guid: GUID) -> Record<LoginPayload> {
    // Local modified time is ignored in upload serialization.
    let modified: Timestamp = 0
    let sortindex = 5_000_000

    let json: JSON = JSON([
        "id": guid,
        "deleted": true,
        ])
    let payload = LoginPayload(json)
    return Record<LoginPayload>(id: guid, payload: payload, modified: modified, sortindex: sortindex)
}

/**
 * Our current local terminology ("logins") has diverged from the terminology in
 * use when Sync was built ("passwords"). I've done my best to draw a sane line
 * between the server collection/record format/etc. and local stuff.
 */
public class LoginsSynchronizer: IndependentRecordSynchronizer, Synchronizer {
    public required init(scratchpad: Scratchpad, delegate: SyncDelegate, basePrefs: Prefs) {
        super.init(scratchpad: scratchpad, delegate: delegate, basePrefs: basePrefs, collection: "passwords")
    }

    override var storageVersion: Int {
        return PasswordsStorageVersion
    }

    func applyIncomingToStorage(storage: SyncableLogins, records: [Record<LoginPayload>], fetched: Timestamp) -> Success {
        func applyRecord(rec: Record<LoginPayload>) -> Success {
            let guid = rec.id
            let payload = rec.payload
            let modified = rec.modified

            // We apply deletions immediately. That might not be exactly what we want -- perhaps you changed
            // a password locally after deleting it remotely -- but it's expedient.
            if payload.deleted {
                return storage.deleteByGUID(guid, deletedAt: modified)
            }

            // If it's not deleted, let's make sure we're using the same GUID locally for this login.
            // TODO

            // Our login storage tracks the shared parent from the last sync (the "mirror").
            // This allows us to conclusively determine what changed in the case of conflict.
            //
            // Once we know that we have a GUID collision for matching records, we can always know which state
            // a record is in:
            //
            // * New remotely only; no local overlay or shared parent in the mirror. Insert it in the mirror.
            //
            // * New both locally and remotely with no shared parent (cocreation). Do a content-based merge
            //   and apply the results remotely, writing the result into the mirror and discarding the overlay
            //   if the upload succeeded. (Doing it in this order allows us to safely replay on failure.)
            //   If the local and remote record are the same, this is trivial.
            //
            // * Changed remotely but not locally. Apply the remote changes to the local mirror. There will be
            //   no local overlay, by definition.
            //
            // * Changed remotely and locally (conflict). Resolve the conflict using a three-way merge: the
            //   local mirror is the shared parent of both the local overlay and the new remote record.
            //   Apply results as in the co-creation case.
            //
            // When a server change is detected (e.g., syncID changes), we should consider shifting the contents
            // of the mirror into the local overlay, allowing a content-based reconciliation to occur on the next
            // full sync. Or we could flag the mirror as to-clear, download the server records and un-clear, and
            // resolve the remainder on completion. This assumes that a fresh start will typically end up with
            // the exact same records, so we might as well keep the shared parents around and double-check.
            return succeed()
        }

        return self.applyIncomingToStorage(records, fetched: fetched, apply: applyRecord)
    }

    // TODO
    func upload() {
        // Find any records for which a local overlay exists. If we want to be really precise,
        // we can find the original server modified time for each record and use it as
        // If-Unmodified-Since on a PUT, or just use the last fetch timestamp, which should
        // be equivalent.
        // New local items might have no GUID (decide!), so assign one if necessary.
        // We will already have reconciled any conflicts on download, so this upload phase should
        // be as simple as uploading any changed or deleted items.
    }

    public func synchronizeLocalLogins(logins: SyncableLogins, withServer storageClient: Sync15StorageClient, info: InfoCollections) -> SyncResult {
        if let reason = self.reasonToNotSync(storageClient) {
            return deferResult(.NotStarted(reason))
        }

        let encoder = RecordEncoder<LoginPayload>(decode: { LoginPayload($0) }, encode: { $0 })
        if let passwordsClient = self.collectionClient(encoder, storageClient: storageClient) {
            let since: Timestamp = self.lastFetched
            log.debug("Synchronizing \(self.collection). Last fetched: \(since).")

            let applyIncomingToStorage: StorageResponse<[Record<LoginPayload>]> -> Success = { response in
                let ts = response.metadata.timestampMilliseconds
                let lm = response.metadata.lastModifiedMilliseconds!
                log.debug("Applying incoming password records from response timestamped \(ts), last modified \(lm).")
                log.debug("Records header hint: \(response.metadata.records)")
                return self.applyIncomingToStorage(logins, records: response.value, fetched: lm)
            }
            return passwordsClient.getSince(since)
                >>== applyIncomingToStorage
                // TODO: upload
                >>> { return deferResult(.Completed) }
        }

        log.error("Couldn't make logins factory.")
        return deferResult(FatalError(message: "Couldn't make logins factory."))
    }
}
