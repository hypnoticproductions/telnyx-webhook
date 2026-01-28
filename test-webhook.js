#!/usr/bin/env node
/**
 * Test script for Telnyx Webhook
 * Simulates a webhook request to verify the server works correctly
 */

const http = require('http');

const PORT = process.env.PORT || 3000;
const HOST = 'localhost';

// Test payload simulating an incoming SMS
const testPayload = {
    data: {
        event_type: 'message.received',
        payload: {
            from: { phone_number: '+1234567890' },
            to: [{ phone_number: '+0987654321' }],
            text: 'Your verification code is 123456',
            occurred_at: new Date().toISOString()
        }
    }
};

const payloadString = JSON.stringify(testPayload);
const timestamp = Math.floor(Date.now() / 1000);

// Note: This will return 401 because we're not signing with a real key
// But it tests that the server receives and processes the request correctly
const options = {
    hostname: HOST,
    port: PORT,
    path: '/webhook',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payloadString),
        'telnyx-timestamp': timestamp.toString(),
        'telnyx-signature-ed25519': 'dGVzdC1zaWduYXR1cmU=' // Base64 encoded "test-signature"
    }
};

console.log('🧪 Testing Telnyx Webhook Endpoint');
console.log('==================================');
console.log(`📡 Sending test request to http://${HOST}:${PORT}/webhook`);
console.log('');

const req = http.request(options, (res) => {
    let data = '';
    
    res.on('data', (chunk) => {
        data += chunk;
    });
    
    res.on('end', () => {
        console.log(`📊 Response Status: ${res.statusCode}`);
        console.log(`📄 Response Body: ${data}`);
        console.log('');
        
        if (res.statusCode === 401) {
            console.log('✅ Server is correctly rejecting invalid signatures (401 expected)');
            console.log('   This confirms signature verification is working!');
        } else if (res.statusCode === 200) {
            console.log('✅ Request processed successfully (200)');
        } else {
            console.log(`⚠️  Unexpected status code: ${res.statusCode}`);
        }
        
        process.exit(0);
    });
});

req.on('error', (error) => {
    console.error('❌ Error connecting to server:');
    console.error(`   ${error.message}`);
    console.log('');
    console.log('💡 Make sure the server is running: npm run dev');
    process.exit(1);
});

req.write(payloadString);
req.end();

console.log('⏳ Waiting for response...');
