const fs = require('fs');
const https = require('https');
const WebSocket = require('ws');
const url = require('url');

// Create HTTPS server with SSL certificate
const server = https.createServer({
    cert: fs.readFileSync('cert.pem'),
    key: fs.readFileSync('key.pem')
});

// Create WebSocket server attached to HTTPS server
const wss = new WebSocket.Server({ server });

const clients = new Map();

wss.on('connection', (ws, req) => {
    const params = new URLSearchParams(url.parse(req.url).query);
    const token = params.get('token');

    if (token !== "password123") {
        console.log(`Unauthorized access attempt from ${req.socket.remoteAddress}`);
        ws.send("Unauthorized access - connection closed.");
        ws.close();
        return;
    }

    console.log(`Authorized access from ${req.socket.remoteAddress}`);
    clients.set(ws, { lastMessageTime: 0 });

    ws.on('message', (message) => {
        if (message === "PING") return; // Ignore heartbeat messages

        const now = Date.now();
        const userData = clients.get(ws);

        if (now - userData.lastMessageTime < 1000) {
            ws.send("You are sending messages too fast");
            return;
        }

        userData.lastMessageTime = now;
        console.log(`Received: ${message}`);

        // Broadcast message to all connected clients
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    });

    ws.on('close', () => {
        clients.delete(ws);
        console.log(`Client disconnected from ${req.socket.remoteAddress}`);
    });
});

// Start WebSocket server on port 5000
server.listen(5000, () => {
    console.log("Secure WebSocket server running on wss://localhost:5000");
});