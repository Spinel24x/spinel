// =============================================
// Copy this entire file to Cloudflare Worker
// NO environment variables needed
// =============================================

// CHANGE THIS to your Railway app URL
const RAILWAY_URL = 'https://your-app.up.railway.app';

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const upgradeHeader = request.headers.get('Upgrade');

        // Handle WebSocket (VLESS connections)
        if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
            const railwayUrl = `${RAILWAY_URL}${url.pathname}${url.search}`;

            const [client, server] = Object.values(new WebSocketPair());

            try {
                const remoteSocket = new WebSocket(railwayUrl);

                client.accept();
                remoteSocket.accept();

                client.addEventListener('message', (event) => {
                    if (remoteSocket.readyState === WebSocket.OPEN) {
                        remoteSocket.send(event.data);
                    }
                });

                remoteSocket.addEventListener('message', (event) => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(event.data);
                    }
                });

                client.addEventListener('close', () => {
                    if (remoteSocket.readyState === WebSocket.OPEN) {
                        remoteSocket.close(1000, 'Client disconnected');
                    }
                });

                remoteSocket.addEventListener('close', () => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.close(1000, 'Server disconnected');
                    }
                });

                client.addEventListener('error', (err) => {
                    console.error('Client error:', err);
                });

                remoteSocket.addEventListener('error', (err) => {
                    console.error('Server error:', err);
                });

                return new Response(null, { status: 101, webSocket: server });
            } catch (err) {
                return new Response('WebSocket connection failed', { status: 502 });
            }
        }

        // Proxy all other requests to Railway (panel, API, static files)
        const targetUrl = `${RAILWAY_URL}${url.pathname}${url.search}`;

        const modifiedRequest = new Request(targetUrl, {
            method: request.method,
            headers: request.headers,
            body: request.method !== 'GET' && request.method !== 'HEAD'
                ? await request.arrayBuffer()
                : null
        });

        return fetch(modifiedRequest);
    }
};
