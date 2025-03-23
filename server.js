const fs = require('fs');
const bcrypt = require('bcrypt');
const https = require('https');
const WebSocket = require('ws');
const url = require('url');

const server = https.createServer({
    cert: fs.readFileSync('cert.pem'),
    key: fs.readFileSync('key.pem')
});

const wss = new WebSocket.Server({ server });

const clients = new Map();

wss.on('connection', async (ws, req) => {
    const params = new URLSearchParams(url.parse(req.url).query);
    const token = params.get('token');

    const hashedPassword = '$2b$10$EIXIXQp1j1bYFZ1Z5r1O0eQe5Z5r1O0eQe5Z5r1O0eQe5Z5r1O0e'; // Example hash

    const authorized = await bcrypt.compare(token, hashedPassword);

    if (!authorized) {
        console.log(`Unauthorized access attempt from ${req.socket.remoteAddress}`);
        ws.send("Unauthorized access - connection closed.");
        ws.close();
        return;
    }

    console.log(`Authorized access from ${req.socket.remoteAddress}`);

    clients.set(ws, { lastMessageTime: 0 });

    ws.on('message', async (message) => {
        if (message === "PING") return; 

        const now = Date.now();
        let userData = clients.get(ws);

        if (!userData) {
            userData = { lastMessageTime: 0 };
            clients.set(ws, userData);
        }

        if (now - userData.lastMessageTime < 1000) {  
            ws.send("You are sending messages too quickly. Please wait.");
            console.log("Rate limit hit: Message blocked");
            return;
        }

        userData.lastMessageTime = now;
        console.log(`Received: ${message}`);

        if (message instanceof Buffer) {
            message = message.toString(); 
        }

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

server.listen(5000, () => {
    console.log("Secure WebSocket server running on wss://localhost:5000");
});