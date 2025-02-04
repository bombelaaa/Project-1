const fs = require('fs');
const https = require('https')
const WebSocket = require('ws');

const server = https.createServer({
    cert: fs.readFileSync('cert.pem'),
    key: fs.readFileSync('key.pem')
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    console.log('Client connected');

    ws.on('message', (message) => {
        console.log(`Received: ${message}`);
        ws.send(`Echo: ${message}`);
    });

    ws.on('close', () => console.log('Client disconnected'));
});

server.listen(5000, () => {
    console.log("Secure WebSocket server running on wss://localhost:5000");
});