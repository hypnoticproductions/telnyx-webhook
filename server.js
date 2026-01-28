/**
 * Telnyx SMS Webhook Handler
 *
 * Receives inbound SMS from Telnyx, verifies Ed25519 signatures,
 * extracts verification codes, sends HTML email notifications via Resend,
 * stores messages in JSONL format, supports multiple recipients, includes
 * rate limiting, and sends Slack notifications on email failures.
 *
 * @author MiniMax Agent
 * @version 2.0.0
 */

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { Resend } = require('resend');
const fs = require('fs').promises;
const path = require('path');

// Initialize Express app with serverless-friendly configuration
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// RATE LIMITING CONFIGURATION
// ============================================================================

// Simple in-memory rate limiter (for serverless, consider Redis via Upstash)
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 30; // 30 requests per minute per IP

/**
 * Simple rate limiting middleware
 * Limits requests per IP address to prevent abuse
 */
function rateLimiter(req, res, next) {
    const identifier = req.ip || req.connection.remoteAddress;
    const now = Date.now();

    // Clean up old entries
    for (const [key, value] of rateLimitStore.entries()) {
        if (now - value.resetTime > RATE_LIMIT_WINDOW) {
            rateLimitStore.delete(key);
        }
    }

    // Get or create rate limit entry
    let entry = rateLimitStore.get(identifier);

    if (!entry || now - entry.resetTime > RATE_LIMIT_WINDOW) {
        entry = { count: 0, resetTime: now };
        rateLimitStore.set(identifier, entry);
    }

    entry.count++;

    if (entry.count > RATE_LIMIT_MAX_REQUESTS) {
        console.warn(`[RATE_LIMIT] IP ${identifier} exceeded rate limit (${entry.count} requests)`);
        return res.status(429).json({
            error: 'Too Many Requests',
            retryAfter: Math.ceil((RATE_LIMIT_WINDOW - (now - entry.resetTime)) / 1000)
        });
    }

    next();
}

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
// MESSAGE STORAGE
// ============================================================================

const MESSAGES_DIR = process.env.MESSAGES_DIR || path.join(__dirname, 'messages');
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

/**
 * Stores message to JSON file with automatic rotation
 * Uses append mode with file size-based rotation
 *
 * @param {Object} messageData - Message to store
 */
async function storeMessage(messageData) {
    try {
        // Ensure messages directory exists
        await fs.mkdir(MESSAGES_DIR, { recursive: true });

        const date = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
        const filename = `messages-${date}.json`;
        const filepath = path.join(MESSAGES_DIR, filename);

        // Create record with timestamp
        const record = {
            timestamp: new Date().toISOString(),
            ...messageData
        };

        // Check if file exists and its size
        let shouldRotate = false;
        try {
            const stats = await fs.stat(filepath);
            if (stats.size > MAX_FILE_SIZE) {
                shouldRotate = true;
            }
        } catch (error) {
            // File doesn't exist, will create new one
        }

        if (shouldRotate) {
            // Rotate file by adding counter suffix
            const timestamp = Date.now();
            const rotatedFilename = `messages-${date}-${timestamp}.json`;
            const rotatedPath = path.join(MESSAGES_DIR, rotatedFilename);
            await fs.rename(filepath, rotatedPath);
        }

        // Append message to file (one JSON object per line - JSONL format)
        await fs.appendFile(filepath, JSON.stringify(record) + '\n', 'utf8');

        console.log(`[STORAGE] Message stored to ${filename}`);
    } catch (error) {
        console.error('[STORAGE] Failed to store message:', error.message);
        // Don't throw - storage failure shouldn't break the webhook
    }
}

// ============================================================================
// ERROR NOTIFICATIONS
// ============================================================================

/**
 * Sends error notification to Slack webhook
 * Used when email sending fails
 *
 * @param {string} errorMessage - Error description
 * @param {Object} context - Additional context
 */
async function notifySlackError(errorMessage, context = {}) {
    const slackWebhookUrl = process.env.SLACK_WEBHOOK_URL;

    if (!slackWebhookUrl) {
        console.warn('[SLACK] SLACK_WEBHOOK_URL not configured, skipping error notification');
        return;
    }

    try {
        const payload = {
            text: `🚨 Telnyx Webhook Error`,
            blocks: [
                {
                    type: "header",
                    text: {
                        type: "plain_text",
                        text: "🚨 Email Notification Failed"
                    }
                },
                {
                    type: "section",
                    fields: [
                        {
                            type: "mrkdwn",
                            text: `*Error:*\n${errorMessage}`
                        },
                        {
                            type: "mrkdwn",
                            text: `*Time:*\n${new Date().toISOString()}`
                        }
                    ]
                },
                {
                    type: "section",
                    text: {
                        type: "mrkdwn",
                        text: `*Context:*\n\`\`\`${JSON.stringify(context, null, 2)}\`\`\``
                    }
                }
            ]
        };

        const response = await fetch(slackWebhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            console.error('[SLACK] Failed to send notification:', response.statusText);
        } else {
            console.log('[SLACK] Error notification sent successfully');
        }
    } catch (error) {
        console.error('[SLACK] Failed to notify Slack:', error.message);
    }
}

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
 * Sends email notification via Resend asynchronously with HTML formatting.
 * Supports multiple recipient numbers in the email.
 * Does NOT block the webhook response - fire-and-forget pattern.
 *
 * @param {Object} messageData - SMS message details
 */
function sendEmailNotification(messageData) {
    const { from, to, toNumbers, body, timestamp, code } = messageData;

    // Initialize Resend client
    const resend = new Resend(process.env.RESEND_API_KEY);

    // Format recipient list (single or multiple)
    const recipientDisplay = toNumbers && toNumbers.length > 1
        ? toNumbers.map(num => `<li>${num}</li>`).join('')
        : `<li>${to}</li>`;

    const recipientText = toNumbers && toNumbers.length > 1
        ? toNumbers.join(', ')
        : to;

    // Build HTML email content
    const emailHtml = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 24px; }
        .content { background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-top: none; }
        .field { margin-bottom: 15px; }
        .field-label { font-weight: 600; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
        .field-value { margin-top: 5px; padding: 10px; background: white; border-radius: 4px; border: 1px solid #e5e7eb; }
        .code-highlight { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 15px 0; border-radius: 4px; }
        .code-highlight strong { color: #d97706; font-size: 24px; letter-spacing: 2px; }
        .message-body { white-space: pre-wrap; word-wrap: break-word; }
        .footer { text-align: center; padding: 15px; color: #9ca3af; font-size: 12px; }
        ul { margin: 5px 0; padding-left: 20px; }
        ul li { margin: 3px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📱 New SMS Received</h1>
        </div>
        <div class="content">
            <div class="field">
                <div class="field-label">From</div>
                <div class="field-value"><strong>${from}</strong></div>
            </div>
            <div class="field">
                <div class="field-label">To ${toNumbers && toNumbers.length > 1 ? '(Multiple Recipients)' : ''}</div>
                <div class="field-value">
                    <ul>
                        ${recipientDisplay}
                    </ul>
                </div>
            </div>
            <div class="field">
                <div class="field-label">Timestamp</div>
                <div class="field-value">${new Date(timestamp).toLocaleString()}</div>
            </div>
            ${code ? `
            <div class="code-highlight">
                <div style="font-size: 14px; margin-bottom: 5px;">🔐 Verification Code Detected:</div>
                <strong>${code}</strong>
            </div>
            ` : ''}
            <div class="field">
                <div class="field-label">Message</div>
                <div class="field-value message-body">${body}</div>
            </div>
        </div>
        <div class="footer">
            Telnyx SMS Webhook Handler
        </div>
    </div>
</body>
</html>`;

    // Build plain text email content as fallback
    const emailText = `Inbound SMS received:
From: ${from}
To: ${recipientText}
Timestamp: ${timestamp}
Message: ${body}
${code ? `\nVerification code detected: ${code}` : ''}`;

    const emailSubject = `${code ? '🔐 ' : ''}New SMS from ${from}`;

    // Send email asynchronously - do NOT await
    resend.emails.send({
        from: process.env.EMAIL_FROM,
        to: process.env.EMAIL_TO,
        subject: emailSubject,
        html: emailHtml,
        text: emailText
    })
    .then((result) => {
        console.log(`[EMAIL] Notification sent successfully to ${process.env.EMAIL_TO}`);
    })
    .catch((error) => {
        // Log error and notify via Slack
        console.error(`[EMAIL] Failed to send notification: ${error.message}`);

        // Send error notification to Slack
        notifySlackError(`Email notification failed: ${error.message}`, {
            from,
            to: recipientText,
            timestamp,
            error: error.message
        });
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
 * Logs details, stores message, and triggers async email notification.
 *
 * @param {Object} payload - Parsed webhook payload
 */
function processIncomingMessage(payload) {
    try {
        // Extract message details from Telnyx payload structure
        const from = payload.from?.phone_number || 'Unknown';

        // Extract all recipient phone numbers (Telnyx supports multiple recipients)
        const toNumbers = payload.to?.map(recipient => recipient.phone_number) || ['Unknown'];
        const to = toNumbers[0]; // Primary recipient for backwards compatibility

        const body = payload.text || payload.body || '';
        const timestamp = payload.occurred_at || new Date().toISOString();

        // Extract potential verification code
        const code = extractVerificationCode(body);

        // Log the incoming message with all recipients
        const recipientsLog = toNumbers.length > 1
            ? `${toNumbers.length} recipients (${toNumbers.join(', ')})`
            : to;

        console.log(`[SMS] Inbound from ${from} to ${recipientsLog} at ${timestamp}: ${body.substring(0, 100)}${body.length > 100 ? '...' : ''}`);

        if (code) {
            console.log(`[SMS] Verification code detected: ${code}`);
        }

        // Store message asynchronously (fire-and-forget)
        const messageData = {
            from,
            to,
            toNumbers,
            body,
            timestamp,
            code,
            messageId: payload.id,
            direction: 'inbound'
        };

        storeMessage(messageData);

        // Trigger async email notification (fire-and-forget)
        sendEmailNotification(messageData);

    } catch (error) {
        console.error('[ERROR] Failed to process incoming message:', error.message);
    }
}

// ============================================================================
// WEBHOOK ENDPOINT
// ============================================================================

app.post('/webhook', rateLimiter, (req, res) => {
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
