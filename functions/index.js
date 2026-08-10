const functions = require("firebase-functions");
const admin = require("firebase-admin");

// Initialize Firebase Admin (Storage bucket is automatically inferred from your Firebase project)
admin.initializeApp();

// Use native Firebase Cloud Storage instead of Backblaze
const bucket = admin.storage().bucket();

/**
 * 1. GENERATE SECURE UPLOAD TETHER
 * Front-end calls this right before sending a zipped payload.
 */
exports.requestSecureUploadLink = functions.https.onCall(async (data, context) => {
    // Force strict mandatory authentication gate verification
    if (!context.auth) {
        throw new functions.https.HttpsError("unauthenticated", "Access denied. Core authentication signature missing.");
    }

    const uid = context.auth.uid; // Un-spoofable User ID pulled directly from the secure token
    const nodeId = data.nodeId;

    if (!nodeId) {
        throw new functions.https.HttpsError("invalid-argument", "Target Crystal Node ID missing from execution payload.");
    }

    // Isolate data lines: Sandboxes the user explicitly to their private folder string
    const fileStorageKey = `vaults/${uid}/${nodeId}_core.zip`;

    try {
        const file = bucket.file(fileStorageKey);

        // Generate a temporary single-use signature that expires in 15 minutes
        const [uploadUrl] = await file.getSignedUrl({
            version: 'v4',
            action: 'write',
            expires: Date.now() + 15 * 60 * 1000, // 15 minutes from now
            contentType: 'application/zip'
        });

        return { success: true, uploadUrl, fileStorageKey };
    } catch (error) {
        console.error("[VAULT_CRITICAL] Failed to generate presigned upload tether:", error);
        throw new functions.https.HttpsError("internal", "Secure upload link generation aborted.");
    }
});

/**
 * 2. GENERATE SECURE DOWNLOAD STREAM LINK
 * Front-end calls this when a user clicks an allocated crystal to view their files.
 */
exports.requestSecureDownloadLink = functions.https.onCall(async (data, context) => {
    if (!context.auth) {
        throw new functions.https.HttpsError("unauthenticated", "Access denied. Core authentication signature missing.");
    }

    const fileStorageKey = data.fileStorageKey;
    const uid = context.auth.uid;

    if (!fileStorageKey) {
        throw new functions.https.HttpsError("invalid-argument", "Requested file storage reference key missing.");
    }

    // HARD SECURITY WALL: Enforce that users can only fetch links pointing to their own subfolders
    if (!fileStorageKey.startsWith(`vaults/${uid}/`)) {
        throw new functions.https.HttpsError("permission-denied", "Intrusion detected. Security signature mismatch.");
    }

    try {
        const file = bucket.file(fileStorageKey);

        // Generate an authorized link valid for 1 hour for internal browser memory extraction
        const [downloadUrl] = await file.getSignedUrl({
            version: 'v4',
            action: 'read',
            expires: Date.now() + 60 * 60 * 1000 // 1 hour from now
        });

        return { success: true, downloadUrl };
    } catch (error) {
        console.error("[VAULT_CRITICAL] Failed to generate presigned acquisition link:", error);
        throw new functions.https.HttpsError("internal", "Secure download path generation aborted.");
    }
});
