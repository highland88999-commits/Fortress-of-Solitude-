const functions = require("firebase-functions");
const admin = require("firebase-admin");
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

admin.initializeApp();

// Dynamically pull from Firebase config (This matches the terminal command you ran)
const s3Client = new S3Client({
    endpoint: "https://s3.us-west-004.backblazeb2.com", // Replace with your exact B2 Endpoint if different
    credentials: {
        accessKeyId: functions.config().b2.key_id,
        secretAccessKey: functions.config().b2.application_key
    },
    region: "us-west-004"
});

const BUCKET_NAME = "olympus-quantum-vault-01";

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
        const command = new PutObjectCommand({
            Bucket: BUCKET_NAME,
            Key: fileStorageKey,
            ContentType: "application/zip"
        });

        // Generate a temporary single-use signature that expires in 15 minutes (900 seconds)
        const uploadUrl = await getSignedUrl(s3Client, command, { expiresIn: 900 });

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
        const command = new GetObjectCommand({
            Bucket: BUCKET_NAME,
            Key: fileStorageKey
        });

        // Generate an authorized link valid for 1 hour (3600 seconds) for internal browser memory extraction
        const downloadUrl = await getSignedUrl(s3Client, command, { expiresIn: 3600 });

        return { success: true, downloadUrl };
    } catch (error) {
        console.error("[VAULT_CRITICAL] Failed to generate presigned acquisition link:", error);
        throw new functions.https.HttpsError("internal", "Secure download path generation aborted.");
    }
});
