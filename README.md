# SecureChat

**Live demo:** [https://securechat-jb.glitch.me/](https://securechat-jb.glitch.me/)

SecureChat is an end-to-end encrypted real-time chat application with secure file sharing, built using Node.js, Express, Socket.IO, OpenPGP.js, and AWS S3 for file storage.

## Features

* **User registration & login** with hashed passwords (bcrypt) and JWT-based authentication.
* **End-to-end encrypted messaging**: messages encrypted client-side using OpenPGP and stored as ciphertext on the server.
* **Real-time chat** via WebSockets (Socket.IO).
* **Presence indicators**: online/offline status tracking.
* **Secure file sharing**: files encrypted client-side, uploaded to AWS S3 via presigned URLs, decrypted client-side upon download.

## Architecture

```
+-------------+     HTTPS/API      +-------------+     MySQL      +-------------+
|   Browser   | <---------------> |   Express   | <------------> |   Database  |
| (client.js) |    Socket.IO/WSS   |   server.js |                +-------------+
+-------------+                    +-------------+
       |                                   |
       |— presigned URLs via REST —> AWS S3 |
       |<— decrypted blob download ————>     |
```

## Getting Started

### Prerequisites

* Node.js (12+)
* MySQL database
* AWS account with an S3 bucket

### Environment Variables

Create a `.env` in `server/`:

```ini
PORT=3000
JWT_SECRET=your_jwt_secret_here
DB_HOST=your_mysql_host
DB_USER=your_db_user
DB_PASS=your_db_password
DB_NAME=your_db_name
AWS_REGION=us-west-2         # your S3 bucket region
S3_BUCKET=your_bucket_name
```

### Installation

1. Clone the repo:

   ```bash
   ```

git clone [https://github.com/bombelaaa/Securechat-JB.git](https://github.com/bombelaaa/Securechat-JB.git)
cd Securechat-JB/server

````
2. Install dependencies:
   ```bash
npm install
````

3. Update `.env` with your credentials.
4. Run database migrations to create tables:

   ```sql
   ```

CREATE TABLE users (
id INT AUTO\_INCREMENT PRIMARY KEY,
username VARCHAR(255) UNIQUE NOT NULL,
hashed\_password VARCHAR(255) NOT NULL,
public\_key TEXT,
encrypted\_private\_key TEXT
);

CREATE TABLE messages (
id INT AUTO\_INCREMENT PRIMARY KEY,
sender\_id INT NOT NULL,
recipient\_id INT NOT NULL,
ciphertext TEXT NOT NULL,
iv VARCHAR(255),
created\_at DATETIME DEFAULT CURRENT\_TIMESTAMP
);

CREATE TABLE presence (
user\_id INT PRIMARY KEY,
last\_seen DATETIME
);

````
5. Start the server:
   ```bash
npm start
````

6. In another folder, serve the `public/` directory (or use Glitch). Point your browser to `http://localhost:3000`.

## API Endpoints

* **GET** `/api/ping` — Health check
* **POST** `/api/register` — `{ username, password, publicKey, encryptedPrivateKey }`
* **POST** `/api/login` — `{ username, password }` ⇒ `{ token, userId, publicKey, encryptedPrivateKey }`
* **GET** `/api/users` — List other users and public keys (requires `Bearer <token>`)
* **GET** `/api/messages/:peerId` — Chat history with another user (requires auth)
* **POST** `/api/upload-url` — `{ fileName, contentType }` ⇒ `{ uploadUrl, fileUrl }`

## Client Flow

1. **Register**: generate PGP keypair (OpenPGP.js), send public key & encrypted private key to server.
2. **Login**: receive JWT + keys, decrypt private key locally.
3. **Load peers**: fetch user list & public keys.
4. **Start socket**: authenticate over WebSocket with JWT.
5. **Messages**: encrypt with peer’s public key, emit `encrypted_message`, server relays & persists.
6. **History**: fetch past ciphertexts via REST, decrypt locally.
7. **File share**: encrypt file, get presigned S3 URL, upload, then `file_message` with S3 link.

## Security

* **Passwords** are salted & hashed (bcrypt).
* **JWT** Secures API and WebSocket auth.
* **End-to-End Encryption**: server never sees plaintext.
* **Presigned URLs** with short TTL protect S3 uploads/downloads.
* **SQL queries** are parameterized to prevent injection.

## Future Improvements

* Rate limiting & brute-force protection.
* Emoji reactions, typing indicators.
* Group chats & channels.
* Desktop notifications & offline message queue.

---

