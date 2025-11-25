const WebSocket = require('ws');

const wss = new WebSocket.Server({ port: 8877 });

console.log('Test WebSocket server listening on port 8877');

wss.on('connection', function connection(ws) {
  console.log('New client connected');
  
  ws.on('message', function incoming(message) {
    console.log('Received:', message.toString());
    
    // Echo back
    ws.send(JSON.stringify({ type: 'echo', data: message.toString() }));
  });
  
  ws.on('close', function() {
    console.log('Client disconnected');
  });
  
  // Send welcome message
  ws.send(JSON.stringify({ type: 'welcome', message: 'Connected to test server' }));
});

console.log('Test with: ws://localhost:8877');