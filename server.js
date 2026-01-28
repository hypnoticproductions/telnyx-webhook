/**
 * Telnyx SMS Webhook Handler
 * 
 * Receives inbound SMS from Telnyx, verifies Ed25519 signatures,
 * extracts verification codes, and sends email notifications via Resend.
 * 
 * @author MiniMax Agent
 * @version 1.0.0
 */

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { Resend } = require('resend');

// Initialize Express app with serverless-friendly configuration
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// MIDDLEWARE CONFIGURATION
// ============================================================================

// Capture raw body for signature verification BEFORE JSON parsing
// This is critical for Ed25519 signature validation
app.use(bodyParser.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));

// Health check endpoint for monitoring and load balancer probes
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// ============================================================================
// SECURITY FUNCTIONS
// ============================================================================

/**
 * Validates that the webhook timestamp is within the acceptable window.
 * Protects against replay attacks using time-based validation.
 * 
 * @param {string} timestamp - Unix timestamp from Telnyx header
 * @returns {boolean} - True if timestamp is valid (within 5 minutes)
 */
function isTimestampValid(timestamp) {
    const webhookTimestamp = parseInt(timestamp, 10);
    
    if (isNaN(webhookTimestamp)) {
        console.warn('[SECURITY] Invalid timestamp format received');
        return false;
    }
    
    const currentTime = Math.floor(Date.now() / 1000);
    const maxAge = 5 * 60; // 5 minutes in seconds
    const timestampAge = currentTime - webhookTimestamp;
    
    if (timestampAge > maxAge) {
        console.warn(`[SECURITY] Timestamp too old: ${timestampAge}s ago (max: ${maxAge}s)`);
        return false;
    }
    
    // Also reject future timestamps (with 60 second tolerance for clock skew)
    if (webhookTimestamp > currentTime + 60) {
        console.warn('[SECURITY] Timestamp is in the future');
        return false;
    }
    
    return true;
}

/**
 * Verifies the Ed25519 signature on the webhook payload.
 * Uses Telnyx's recommended signature verification method.
 * 
 * @param {string} rawBody - Raw request body as string
 * @param {string} timestamp - Telnyx timestamp header
 * @param {string} signatureHeader - Base64-encoded Ed25519 signature
 * @returns {boolean} - True if signature is valid
 */
function verifySignature(rawBody, timestamp, signatureHeader) {
    try {
        // Get the public key from environment (base64 encoded)
        const publicKeyBase64 = process.env.TELNYX_PUBLIC_KEY;
        
        if (!publicKeyBase64) {
            console.error('[SECURITY] TELNYX_PUBLIC_KEY not configured');
            return false;
        }
        
        // Decode the public key from base64
        const publicKey = Buffer.from(publicKeyBase64, 'base64');
        
        // Decode the signature from base64
        const signature = Buffer.from(signatureHeader, 'base64');
        
        // Construct the signed payload: timestamp|rawBody
        // This matches Telnyx's expected signing format
        const signedPayload = `${timestamp}|${rawBody}`;
        const signedPayloadBuffer = Buffer.from(signedPayload, 'utf8');
        
        // Verify the Ed25519 signature
        // Algorithm null specifies Ed25519 in Node.js crypto
        const isValid = crypto.verify(null, signedPayloadBuffer, publicKey, signature);
        
        if (!isValid) {
            console.warn('[SECURITY] Signature verification failed');
        }
        
        return isValid;
        
    } catch (error) {
        console.error('[SECURITY] Error during signature verification:', error.message);
        return false;
    }
}

// ============================================================================
// EMAIL NOTIFICATION (FIRE-AND-FORGET)
// ============================================================================

/**
 * Sends email notification via Resend asynchronously.
 * Does NOT block the webhook response - fire-and-forget pattern.
 * 
 * @param {Object} messageData - SMS message details
 */
function sendEmailNotification(messageData) {
    const { from, to, body, timestamp, code } = messageData;
    
    // Initialize Resend client
    const resend = new Resend(process.env.RESEND_API_KEY);
    
    // Build email content
    const emailText = `Inbound SMS received:
From: ${from}
To: ${to}
Timestamp: ${timestamp}
Message: ${body}
${code ? `\nVerification code detected: ${code}` : ''}`;

    const emailSubject = `New SMS from ${from}`;
    
    // Send email asynchronously - do NOT await
    resend.emails.send({
        from: process.env.EMAIL_FROM,
        to: process.env.EMAIL_TO,
        subject: emailSubject,
        text: emailText
    })
    .then((result) => {
        console.log(`[EMAIL] Notification sent successfully to ${process.env.EMAIL_TO}`);
    })
    .catch((error) => {
        // Log error but don't throw - email failure shouldn't affect webhook response
        console.error(`[EMAIL] Failed to send notification: ${error.message}`);
    });
}

// ============================================================================
// MESSAGE PROCESSING
// ============================================================================

/**
 * Extracts a potential verification code from SMS body.
 * Looks for 4-6 digit sequences (common 2FA code format).
 * 
 * @param {string} body - SMS message body
 * @returns {string|null} - Extracted code or null
 */
function extractVerificationCode(body) {
    if (!body) return null;
    
    // Match 4-6 digit sequences (common 2FA/verification code format)
    const match = body.match(/\b\d{4,6}\b/);
    return match ? match[0] : null;
}

/**
 * Processes an incoming SMS message.
 * Logs details and triggers async email notification.
 * 
 * @param {Object} payload - Parsed webhook payload
 */
function processIncomingMessage(payload) {
    try {
        // Extract message details from Telnyx payload structure
        const from = payload.from?.phone_number || 'Unknown';
        const to = payload.to?.[0]?.phone_number || 'Unknown';
        const body = payload.text || payload.body || '';
        const timestamp = payload.occurred_at || new Date().toISOString();
        
        // Extract potential verification code
        const code = extractVerificationCode(body);
        
        // Log the incoming message (summary only for production safety)
        console.log(`[SMS] Inbound from ${from} to ${to} at ${timestamp}: ${body.substring(0, 100)}${body.length > 100 ? '...' : ''}`);
        
        if (code) {
            console.log(`[SMS] Verification code detected: ${code}`);
        }
        
        // Trigger async email notification (fire-and-forget)
        sendEmailNotification({ from, to, body, timestamp, code });
        
    } catch (error) {
        console.error('[ERROR] Failed to process incoming message:', error.message);
    }
}

// ============================================================================
// WEBHOOK ENDPOINT
// ============================================================================

app.post('/webhook', (req, res) => {
    try {
        // =========================================================================
        // STEP 1: Validate required headers
        // =========================================================================
        const timestamp = req.headers['telnyx-timestamp'];
        const signature = req.headers['telnyx-signature-ed25519'];
        
        if (!timestamp || !signature) {
            console.warn('[SECURITY] Missing required webhook headers');
            return res.status(401).json({ error: 'Unauthorized - Missing required headers' });
        }
        
        // =========================================================================
        // STEP 2: Validate timestamp (prevent replay attacks)
        // =========================================================================
        if (!isTimestampValid(timestamp)) {
            return res.status(401).json({ error: 'Unauthorized - Invalid or expired timestamp' });
        }
        
        // =========================================================================
        // STEP 3: Verify Ed25519 signature
        // =========================================================================
        if (!req.rawBody) {
            console.error('[SECURITY] Raw body not available for signature verification');
            return res.status(401).json({ error: 'Unauthorized - Unable to verify signature' });
        }
        
        const isSignatureValid = verifySignature(req.rawBody, timestamp, signature);
        
        if (!isSignatureValid) {
            return res.status(401).json({ error: 'Unauthorized - Invalid signature' });
        }
        
        // =========================================================================
        // STEP 4: Parse and validate JSON payload
        // =========================================================================
        if (!req.body || !req.body.data) {
            console.warn('[WEBHOOK] Empty or malformed payload received');
            return res.status(400).json({ error: 'Bad Request - Invalid payload' });
        }
        
        // =========================================================================
        // STEP 5: Check event type
        // =========================================================================
        const eventType = req.body.data.event_type;
        
        if (eventType !== 'message.received') {
            // Log but still return 200 for other event types (Telnyx may send other events)
            console.log(`[WEBHOOK] Ignored event type: ${eventType}`);
            return res.status(200).json({ status: 'ignored', event_type: eventType });
        }
        
        // =========================================================================
        // STEP 6: Process the incoming message
        // =========================================================================
        // Extract the actual message payload from Telnyx's nested structure
        const messagePayload = req.body.data.payload || req.body.data;
        processIncomingMessage(messagePayload);
        
        // =========================================================================
        // STEP 7: Return 200 OK immediately (Telnyx requires response within ~5s)
        // =========================================================================
        return res.status(200).json({ status: 'received' });
        
    } catch (error) {
        console.error('[ERROR] Webhook processing failed:', error.message);
        // Still return 200 to prevent Telnyx retries on non-signature errors
        // Signature errors should have already returned 401
        return res.status(200).json({ status: 'error', message: 'Processing error' });
    }
});

// ============================================================================
// ERROR HANDLING MIDDLEWARE
// ============================================================================

// 404 handler for undefined routes
app.use((req, res) => {
    res.status(404).json({ error: 'Not Found' });
});

// Global error handler for unexpected exceptions
app.use((err, req, res, next) => {
    console.error('[ERROR] Unhandled exception:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
});

// ============================================================================
// SERVER STARTUP (for local development)
// ============================================================================

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`[SERVER] Telnyx webhook server running on port ${PORT}`);
        console.log(`[SERVER] Health check: GET http://localhost:${PORT}/health`);
        console.log(`[SERVER] Webhook endpoint: POST http://localhost:${PORT}/webhook`);
    });
}

// Export for Vercel serverless functions
module.exports = app;
