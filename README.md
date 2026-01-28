# Telnyx SMS Webhook Handler

A production-ready, Vercel-deployable Node.js application that securely receives inbound SMS messages via Telnyx webhooks, verifies cryptographic signatures, extracts potential verification codes (4-6 digits commonly used in 2FA), and sends email notifications through Resend.

## Features

- **Secure Signature Verification**: Ed25519 cryptographic signature validation to prevent webhook spoofing
- **Timestamp Validation**: Rejects requests older than 5 minutes to prevent replay attacks
- **Verification Code Extraction**: Automatically detects 4-6 digit codes commonly used in 2FA (Facebook, WhatsApp, etc.)
- **HTML Email Notifications**: Beautiful, responsive HTML emails via Resend with verification code highlighting
- **Multiple Recipient Support**: Handles and displays all recipient phone numbers in logs and emails
- **Message Storage**: Automatic JSONL file storage with 5MB rotation for message archival
- **Error Notifications**: Slack webhook integration for email delivery failures
- **Rate Limiting**: Built-in rate limiting (30 req/min per IP) to prevent webhook abuse
- **Serverless-Ready**: Optimized for Vercel deployment with zero configuration
- **Production Security**: No hard-coded secrets, proper error handling, minimal logging of sensitive data

## Quick Start

### Prerequisites

- Node.js 18+ installed locally
- A Telnyx account with a phone number and Messaging Profile
- A Resend account for email delivery
- GitHub account for version control

### Local Development Setup

1. **Clone and install dependencies**:

```bash
git clone <your-repository-url>
cd telnyx-webhook
npm install
```

2. **Create environment file**:

Create a `.env` file in the project root:

```env
# Telnyx webhook signing key (base64 encoded from Telnyx portal)
TELNYX_PUBLIC_KEY=your_base64_encoded_public_key_here

# Resend API key (get from https://resend.com)
RESEND_API_KEY=re_123456789

# Email configuration
EMAIL_FROM=onboarding@resend.dev  # Must be a verified sender in Resend
EMAIL_TO=your-email@example.com    # Your email address for notifications
```

3. **Get your Telnyx public key**:

   - Log into the [Telnyx Portal](https://portal.telnyx.com)
   - Navigate to **Messaging** → **Numbers** or **Messaging Profiles**
   - Find your webhook signing public key (or generate a new key pair)
   - Copy the public key (it will be base64 encoded)
   - Add it to your `.env` file

4. **Start the development server**:

```bash
npm run dev
```

The server will start on `http://localhost:3000`.

5. **Test locally with ngrok**:

For local testing, expose your server to the internet:

```bash
# Install ngrok if you haven't
npm install -g ngrok

# In a separate terminal, tunnel port 3000
ngrok http 3000
```

Note the HTTPS URL (e.g., `https://abc123.ngrok.io`) for the Telnyx webhook configuration.

## Deployment to Vercel

### Option 1: Deploy from GitHub (Recommended)

1. **Push your code to GitHub**:

```bash
git add .
git commit -m "Initial commit: Telnyx webhook handler"
git push origin main
```

2. **Import to Vercel**:

   - Go to [Vercel Dashboard](https://vercel.com/dashboard)
   - Click **"Add New..."** → **"Project"**
   - Import your GitHub repository
   - Vercel should auto-detect the settings (framework preset: Other)

3. **Configure environment variables**:

   In the Vercel project settings, add these environment variables:

   | Variable | Value | Required |
   |----------|-------|----------|
   | `TELNYX_PUBLIC_KEY` | Your base64-encoded Telnyx public key | Yes |
   | `RESEND_API_KEY` | Your Resend API key (starts with `re_`) | Yes |
   | `EMAIL_FROM` | Verified sender (e.g., `onboarding@resend.dev`) | Yes |
   | `EMAIL_TO` | Your email address for notifications | Yes |
   | `SLACK_WEBHOOK_URL` | Slack webhook URL for error notifications | No |
   | `MESSAGES_DIR` | Directory for message storage (default: `./messages`) | No |

4. **Deploy**:

   Click **"Deploy"** and wait for the build to complete.

5. **Get your production URL**:

   Note your Vercel deployment URL (e.g., `https://your-project.vercel.app`)

### Option 2: Deploy with Vercel CLI

```bash
# Install Vercel CLI globally
npm i -g vercel

# Login to Vercel
vercel login

# Deploy to production
vercel --prod
```

## Configure Telnyx Webhook

1. **Log into Telnyx Portal**:

   Navigate to [Telnyx Portal](https://portal.telnyx.com)

2. **Configure your Messaging Profile**:

   - Go to **Messaging** → **Messaging Profiles**
   - Select your Messaging Profile (or create a new one)
   - Click **"Edit"** or navigate to the **"Numbers"** section

3. **Assign phone numbers** (if not already assigned):

   - In your Messaging Profile, go to **"Numbers"**
   - Click **"Buy Number"** or **"Assign Number"**
   - Assign your desired phone number(s) to this profile

4. **Set the webhook URL**:

   - In your Messaging Profile, find the **"Inbound Settings"** or **"Webhooks"** section
   - Set **"Inbound Webhook URL"** to:
   
   ```
   https://your-vercel-app.vercel.app/webhook
   ```
   
   Replace `your-vercel-app` with your actual Vercel project name.

5. **Save configuration**:

   Click **"Save"** or **"Apply"** to activate the webhook.

## How It Works

### Webhook Processing Flow

```
1. Telnyx sends POST to /webhook with SMS data
2. Server validates required headers (timestamp, signature)
3. Timestamp is checked (must be within 5 minutes)
4. Ed25519 signature is verified using TELNYX_PUBLIC_KEY
5. If valid: Parse payload, extract message details
6. Scan message body for 4-6 digit verification codes
7. Send email notification via Resend (async, non-blocking)
8. Return 200 OK immediately (Telnyx requires <5s response)
```

### Signature Verification Details

Telnyx signs webhooks using Ed25519 (a modern elliptic curve signature scheme). The signature is computed over:

```
{ telnyx-timestamp }|{ raw_request_body }
```

This creates a unique signature for each request that:
- Cannot be forged without the private key
- Cannot be replayed with an old timestamp
- Verifies the exact payload wasn't modified in transit

### Handling Multiple Phone Numbers

All phone numbers assigned to the same Messaging Profile will send their inbound webhooks to the same URL. The payload includes the destination phone number (`payload.to[0].phone_number`), so you can:

- Handle multiple numbers with a single webhook endpoint
- Filter or route based on the destination number
- Track which number received each message

## Advanced Features

### HTML Email Formatting

Emails are sent with beautiful HTML formatting that includes:

- **Gradient header** with clear subject line
- **Structured field display** for From, To (with multiple recipients), and Timestamp
- **Highlighted verification codes** with yellow background and large text
- **Responsive design** that works on all email clients
- **Plain text fallback** for email clients that don't support HTML

Example email features:
- Verification codes are displayed in 24px bold text with visual highlighting
- Multiple recipients are shown in a bulleted list
- Timestamps are formatted in locale-specific format
- Message body preserves whitespace and line breaks

### Message Storage

All incoming messages are automatically stored in JSONL (JSON Lines) format:

- **Location**: `./messages/` directory (configurable via `MESSAGES_DIR`)
- **Format**: One JSON object per line for easy parsing and streaming
- **File naming**: `messages-YYYY-MM-DD.json` (daily rotation)
- **Auto-rotation**: Files are rotated when they exceed 5MB
- **Gitignored**: The messages directory is automatically excluded from git

Each stored message includes:
```json
{
  "timestamp": "2026-01-28T12:00:00.000Z",
  "from": "+1234567890",
  "to": "+0987654321",
  "toNumbers": ["+0987654321", "+1122334455"],
  "body": "Your verification code is 123456",
  "code": "123456",
  "messageId": "telnyx-message-id",
  "direction": "inbound"
}
```

To read stored messages:
```bash
# View all messages from today
cat messages/messages-$(date +%Y-%m-%d).json

# Parse with jq
cat messages/messages-*.json | jq -s '.'

# Count messages
wc -l messages/messages-*.json
```

### Error Notifications via Slack

When email delivery fails, the system can automatically notify you via Slack:

1. **Create a Slack Incoming Webhook**:
   - Go to your Slack workspace settings
   - Navigate to "Apps" → "Incoming Webhooks"
   - Create a new webhook and copy the URL

2. **Configure the webhook URL**:
   ```env
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
   ```

3. **Automatic notifications**:
   - Triggered only when Resend email delivery fails
   - Includes error message, timestamp, and message context
   - Formatted with Slack blocks for easy reading
   - Does not block webhook processing

### Rate Limiting

Built-in rate limiting protects your webhook from abuse:

- **Limit**: 30 requests per minute per IP address
- **Method**: In-memory tracking (resets on server restart)
- **Response**: HTTP 429 (Too Many Requests) with `retryAfter` header
- **Auto-cleanup**: Old entries are automatically removed

For serverless deployments (Vercel), consider using Redis via Upstash for persistent rate limiting across function invocations:

```javascript
// Example: Upgrade to Redis-based rate limiting
// npm install @upstash/redis
const { Redis } = require('@upstash/redis');
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_URL,
  token: process.env.UPSTASH_REDIS_TOKEN
});
```

### Multiple Recipients Support

The webhook handler now properly supports messages sent to multiple phone numbers:

- **Logs**: Show all recipients with count (e.g., "2 recipients (+1111111111, +2222222222)")
- **Emails**: Display all recipients in a bulleted list with "(Multiple Recipients)" label
- **Storage**: Stores both primary recipient (`to`) and full array (`toNumbers`)

## Testing

### Local Testing

1. **Start your server**:

```bash
npm run dev
```

2. **Test with curl**:

```bash
curl -X POST http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -H "telnyx-timestamp: $(date +%s)" \
  -H "telnyx-signature-ed25519: invalid_signature" \
  -d '{"data": {"event_type": "message.received", "payload": {"from": {"phone_number": "+1234567890"}, "to": [{"phone_number": "+0987654321"}], "text": "Test message"}}}'
```

3. **Check logs** for incoming message and verification code detection.

### Production Testing

1. **Send an actual SMS** to your Telnyx phone number from a personal phone.

2. **Monitor Vercel logs**:

   - Go to your Vercel project dashboard
   - Click **"Deployments"** → select the latest deployment
   - Click **"Logs"** to view real-time logs
   - Look for `[SMS]` log entries showing incoming messages

3. **Check your email** for the notification from Resend.

### Testing Verification Code Extraction

Send a message containing a 4-6 digit code to test the extraction:

- `Your verification code is 123456`
- `Facebook: 582941`
- `WhatsApp code: 42`
  - Note: 2-digit codes won't match (regex requires 4-6 digits)

Expected log output:
```
[SMS] Inbound from +1234567890 to +0987654321 at 2026-01-28T19:30:00Z: Your verification code is 123456
[SMS] Verification code detected: 123456
```

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `TELNYX_PUBLIC_KEY` | Yes | Base64-encoded Ed25519 public key from Telnyx portal |
| `RESEND_API_KEY` | Yes | Resend API key (get from resend.com API keys section) |
| `EMAIL_FROM` | Yes | Verified sender email address (e.g., `onboarding@resend.dev`) |
| `EMAIL_TO` | Yes | Recipient email address for notifications |
| `SLACK_WEBHOOK_URL` | No | Slack incoming webhook URL for error notifications (optional) |
| `MESSAGES_DIR` | No | Directory for message storage (default: `./messages`) |
| `PORT` | No | Port for local development (default: 3000) |

### Getting Your Telnyx Public Key

1. Log into [Telnyx Portal](https://portal.telnyx.com)
2. Navigate to **Messaging** → **Messaging Profiles**
3. Select your profile or create one
4. Look for **"Webhook Signing Key"** or **"Public Key"** in the settings
5. Copy the key (it should be a base64-encoded string)
6. If no key exists, you may need to generate one via the API or contact Telnyx support

## Extension Points

The code is designed for easy extension. Here are some ideas:

### Upgrade to Database Storage

Replace the JSONL file storage with a database:

```javascript
// In processIncomingMessage():
// Use Upstash Redis, Supabase, or MongoDB
// await redis.set(`message:${messageId}`, JSON.stringify(messageData));
```

### Send to GitHub Issue

```javascript
// After processing message:
// Create GitHub issue with verification code
// await createGitHubIssue(code, { from, body });
```

### Send Message Notifications to Slack

```javascript
// In processIncomingMessage():
// Send all messages (not just errors) to Slack
// await sendSlackMessage({ from, body, code });
```

### Retry Failed Emails

```javascript
// Wrap Resend call with retry logic
// await retry(() => resend.emails.send(...), { retries: 3 });
```

### Custom Verification Code Patterns

```javascript
// In extractVerificationCode():
// Support different code formats
const patterns = [
  /\b\d{4,6}\b/,           // 4-6 digits
  /\b[A-Z]{2}\d{4}\b/,     // 2 letters + 4 digits (e.g., AB1234)
  /\b\d{3}-\d{3}\b/        // 3-3 format (e.g., 123-456)
];
```

## Security Considerations

- **Never commit secrets**: Always use environment variables
- **Validate timestamps**: Prevents replay attacks
- **Verify signatures**: Ensures webhook authenticity
- **Minimal payload logging**: Only logs summaries, never full payloads in production
- **Async notifications**: Email failures don't affect webhook response
- **Proper error handling**: No stack traces leaked to callers

## Troubleshooting

### "401 Unauthorized" Responses

1. **Check environment variables**: Ensure `TELNYX_PUBLIC_KEY` is set correctly
2. **Verify key format**: The key must be base64-encoded (copy exactly as shown in Telnyx portal)
3. **Check timestamp**: Ensure your server clock is accurate (NTP synchronized)

### No Email Received

1. **Verify Resend API key**: Check for typos in `RESEND_API_KEY`
2. **Check sender verification**: `EMAIL_FROM` must be verified in Resend
3. **Check spam folder**: Email might be in spam/junk
4. **Review logs**: Look for `[EMAIL]` log entries

### Webhook Not Triggering

1. **Check Telnyx configuration**: Verify webhook URL is correct in Messaging Profile
2. **Test health endpoint**: `GET https://your-app.vercel.app/health`
3. **Check Vercel logs**: Look for incoming requests in deployment logs
4. **Verify phone number assignment**: Ensure number is assigned to the Messaging Profile

### Local Testing Issues

1. **Use ngrok**: Telnyx cannot reach localhost directly
2. **Check ngrok URL**: Ensure you're using the HTTPS URL
3. **Update Telnyx**: Temporarily update webhook URL in Telnyx portal to ngrok URL for testing

## License

MIT License - feel free to use in your projects.

## Support

For issues with:
- **Telnyx webhooks**: Contact Telnyx support or check their documentation
- **Resend emails**: Check Resend documentation or support
- **This code**: Review logs and ensure all environment variables are configured correctly
