// Package pack checks an evidence pack: the folder, or archive of one, that
// holds a review's register, its collection and workflow logs, the stored
// collections, and a manifest of digests.
//
// A check shows that the files are the ones this manifest names, that each log
// agrees with itself and its anchor, and that the manifest, campaign.json and
// the workflow log name the same collections and the same lock, and each log
// ends where the manifest says it does.
// Nothing inside a pack ties its manifest to anything outside it: files, logs,
// anchors and manifest rewritten together agree. The digest of the manifest is
// reported so that it can be compared with the record the service keeps of the
// manifests it hands out, obtained from the service and not from whoever handed
// over the pack. A stored collection is tied to the log only by the
// digest the manifest lists for the file. The check does not show who made the
// pack or when, or that what the logs record is true; a pass is not proof
// against alteration.
//
// The pack is read where it is. A folder is opened through os.Root and an
// archive is read in place, entry by entry, with limits on how much it may
// expand to; nothing is extracted or written, and nothing is executed.
// docs/evidence-format.md specifies the pack.
package pack
