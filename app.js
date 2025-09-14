// Global variables
let customCursor, cursorTrail;
let typingInterval;

// Initialize EmailJS
(function () {
  emailjs.init("U03OzJ14EFXwmPggb"); // Replace with your actual EmailJS public key
})();

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("contact-form");
  const nameInput = document.getElementById("name");
  const emailInput = document.getElementById("email");
  const messageInput = document.getElementById("message");

  // Handle form submit
  form.addEventListener("submit", function (e) {
    e.preventDefault();

    // validate
    if (!validateForm()) return;

    // Send email
    emailjs
      .send(
        "service_l5co76c", // replace with EmailJS service ID
        "template_6il784g", // replace with EmailJS template ID
        {
          from_name: nameInput.value,
          from_email: emailInput.value,
          message: messageInput.value,
        }
      )
      .then(
        () => {
          alert("✅ Thanks for contacting me. I’ll get back to you soon!");
          form.reset();
        },
        (error) => {
          console.error("[CONTACT_ERROR]: ", error);
          alert("❌ Something went wrong. Try again later.");
        }
      );
  });

  // Validation function
  function validateForm() {
    const name = nameInput.value.trim();
    const email = emailInput.value.trim().toLowerCase();
    const message = messageInput.value.trim();

    const email_regex =
      /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

    if (name.length < 3) {
      alert("⚠️ Name should be at least 3 characters.");
      return false;
    }

    if (!email.match(email_regex)) {
      alert("⚠️ Enter a valid email address.");
      return false;
    }

    if (message.length < 5) {
      alert("⚠️ Message should be at least 5 characters.");
      return false;
    }

    return true;
  }
});

// Project data
const projectsData = [
    {
        filename: "threat_hunting.py",
        title: "Advanced Threat Hunting",
        description: "Custom Python scripts for hunting APTs using SIEM data correlation and behavioral analysis",
        tools: ["python", "splunk", "sigma-rules", "mitre-attack"],
        impact: "Detected 3 previously unknown threats",
        details: `
#!/usr/bin/env python3
# Advanced Threat Hunting Framework
# Author: Z3roTrac3
# Purpose: Hunt for APTs using behavioral analysis
# Note: This is representational code for portfolio purposes

import splunk_sdk as splunk
import json
import numpy as np
from sklearn.cluster import DBSCAN

class ThreatHunter:
    def __init__(self):
        self.splunk_host = "siem.internal"
        self.hunting_rules = self.load_sigma_rules()
        
    def hunt_lateral_movement(self):
        query = '''
        index=windows EventCode=4624 OR EventCode=4625
        | eval hour=strftime(_time,"%H")
        | stats count by src_ip, dest_ip, hour, user
        | where count > 50
        '''
        return self.execute_hunt(query)
        
    def detect_data_exfiltration(self):
        # Behavioral analysis for unusual data flows
        anomalies = self.analyze_network_flows()
        return self.correlate_with_mitre_tactics(anomalies)

## Results:
- Detected APT29 lateral movement campaign
- Identified C2 communications via DNS tunneling  
- Uncovered insider threat data exfiltration
        `
    },
    {
        filename: "incident_response.sh",
        title: "IR Automation Framework",
        description: "Bash-based incident response automation reducing response time from hours to minutes",
        tools: ["bash", "osquery", "volatility", "yara"],
        impact: "40% faster incident containment",
        details: `
#!/bin/bash
# Incident Response Automation Framework
# Z3roTrac3
# Note: This is representational code for portfolio purposes

IR_LOG="/var/log/incident_response.log"
QUARANTINE_DIR="/quarantine"
EVIDENCE_DIR="/evidence/$(date +%Y%m%d_%H%M%S)"

incident_response() {
    local alert_type=$1
    local target_host=$2
    
    echo "[$(date)] IR: Processing $alert_type on $target_host" >> $IR_LOG
    
    # Phase 1: Containment
    isolate_host $target_host
    
    # Phase 2: Evidence Collection
    collect_memory_dump $target_host
    collect_disk_artifacts $target_host
    collect_network_logs $target_host
    
    # Phase 3: Analysis
    run_yara_scan $EVIDENCE_DIR
    run_volatility_analysis $EVIDENCE_DIR
    
    # Phase 4: Reporting
    generate_ir_report $alert_type $target_host
}

isolate_host() {
    ssh root@$1 "iptables -A INPUT -j DROP"
    echo "[$(date)] Host $1 isolated" >> $IR_LOG
}

## Deployment Results:
- Mean time to containment: 4.2 minutes (down from 47 minutes)
- Evidence collection automated: 95% faster
- False positive reduction: 67%
        `
    },
    {
        filename: "vuln_assessment.nmap",
        title: "Vulnerability Scanner",
        description: "Custom Nmap NSE scripts for specialized vulnerability detection in IoT devices",
        tools: ["nmap", "nse", "lua", "shodan-api"],
        impact: "Discovered 0-day in IoT firmware",
        details: `
# Custom Nmap Vulnerability Assessment
# Target: IoT Infrastructure Assessment
# Author: Z3roTrac3
#Note: This is representational code for portfolio purposes

nmap -sS -sV --script vuln,exploit \
     --script-args vulns.shodan-api-key=$API_KEY \
     -oA iot_assessment_$(date +%Y%m%d) \
     192.168.100.0/24

## Custom NSE Script: iot-firmware-check.nse
local nmap = require "nmap"
local shortport = require "shortport"
local vulns = require "vulns"

description = [[
Checks for common IoT firmware vulnerabilities
]]

portrule = shortport.port_or_service({80, 443, 8080}, {"http", "https"})

action = function(host, port)
    local vuln = {
        title = "IoT Firmware Information Disclosure",
        state = vulns.STATE.NOT_VULN,
        description = [[
        Checks for firmware version disclosure in IoT devices
        ]],
        references = {
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-XXXXX'
        }
    }
    
    local response = http.get(host, port, "/system/firmware")
    if response and response.body:match("firmware_version") then
        vuln.state = vulns.STATE.VULN
    end
    
    return vulns.Report:new(SCRIPT_NAME, host, port):make_output(vuln)
end

## Results:
- Discovered buffer overflow in firmware update mechanism
- CVE-2023-XXXXX assigned and disclosed responsibly
- Affected 50,000+ IoT devices globally
        `
    }
];

// Interactive tools data
const interactiveTools = {
    'ip-scanner': {
        name: 'IP Scanner',
        command: 'scan_ip.sh',
        interface: `
            <div class="command-line">
                <span class="prompt">user@hackr:~/tools$ </span>
                <span class="command">./scan_ip.sh</span>
            </div>
            <div class="output">
                <div class="tool-input-group">
                    <span style="color: #00d4ff;">Enter target IP:</span>
                    <input type="text" class="tool-input" id="ip-target" placeholder="192.168.1.1">
                    <button class="tool-execute" onclick="executeIpScan()">SCAN</button>
                </div>
                <div id="ip-scan-output" class="tool-output" style="display: none;"></div>
            </div>
        `
    },
    'port-scanner': {
        name: 'Port Scanner',
        command: 'port_scan.sh',
        interface: `
            <div class="command-line">
                <span class="prompt">user@hackr:~/tools$ </span>
                <span class="command">./port_scan.sh</span>
            </div>
            <div class="output">
                <div class="tool-input-group">
                    <span style="color: #00d4ff;">Target IP:</span>
                    <input type="text" class="tool-input" id="port-target" placeholder="192.168.1.1">
                    <button class="tool-execute" onclick="executePortScan()">SCAN PORTS</button>
                </div>
                <div id="port-scan-output" class="tool-output" style="display: none;"></div>
            </div>
        `
    },
    'hash-decoder': {
        name: 'Hash Decoder',
        command: 'crack_hash.py',
        interface: `
            <div class="command-line">
                <span class="prompt">user@hackr:~/tools$ </span>
                <span class="command">python3 crack_hash.py</span>
            </div>
            <div class="output">
                <div class="tool-input-group">
                    <span style="color: #00d4ff;">Hash to crack:</span>
                    <input type="text" class="tool-input" id="hash-input" placeholder="5d41402abc4b2a76b9719d911017c592">
                    <button class="tool-execute" onclick="executeHashCrack()">CRACK</button>
                </div>
                <div id="hash-crack-output" class="tool-output" style="display: none;"></div>
            </div>
        `
    },
    'network-ping': {
        name: 'Network Ping',
        command: 'ping_sweep.sh',
        interface: `
            <div class="command-line">
                <span class="prompt">user@hackr:~/tools$ </span>
                <span class="command">./ping_sweep.sh</span>
            </div>
            <div class="output">
                <div class="tool-input-group">
                    <span style="color: #00d4ff;">Network range:</span>
                    <input type="text" class="tool-input" id="ping-target" placeholder="192.168.1.0/24">
                    <button class="tool-execute" onclick="executePingSweep()">PING SWEEP</button>
                </div>
                <div id="ping-sweep-output" class="tool-output" style="display: none;"></div>
            </div>
        `
    },
    'packet-sniffer': {
        name: 'Packet Sniffer',
        command: 'sniff_traffic.py',
        interface: `
            <div class="command-line">
                <span class="prompt">user@hackr:~/tools$ </span>
                <span class="command">python3 sniff_traffic.py</span>
            </div>
            <div class="output">
                <div class="tool-input-group">
                    <span style="color: #00d4ff;">Interface:</span>
                    <select class="tool-input" id="interface-select">
                        <option value="eth0">eth0</option>
                        <option value="wlan0">wlan0</option>
                        <option value="any">any</option>
                    </select>
                    <button class="tool-execute" onclick="executePacketSniff()">START SNIFFING</button>
                </div>
                <div id="packet-sniff-output" class="tool-output" style="display: none;"></div>
            </div>
        `
    }
};

// DOM Content Loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize immediately without waiting
    setTimeout(() => {
        initializeCustomCursor();
        initializeLoadingScreen();
    }, 100);
});

// Custom Cursor Implementation
function initializeCustomCursor() {
    customCursor = document.querySelector('.custom-cursor');
    cursorTrail = document.querySelector('.cursor-trail');
    
    if (!customCursor || !cursorTrail) return;
    
    let mouseX = 0, mouseY = 0;
    let trailX = 0, trailY = 0;

    document.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
        
        customCursor.style.left = mouseX - 10 + 'px';
        customCursor.style.top = mouseY - 10 + 'px';
    });

    // Cursor trail animation
    function animateTrail() {
        trailX += (mouseX - trailX) * 0.1;
        trailY += (mouseY - trailY) * 0.1;
        
        cursorTrail.style.left = trailX - 2 + 'px';
        cursorTrail.style.top = trailY - 2 + 'px';
        
        requestAnimationFrame(animateTrail);
    }
    animateTrail();

    // Hover effects
    document.addEventListener('mouseenter', (e) => {
        if (e.target.matches('button, .nav-link, .file-item, .tool-button')) {
            customCursor.style.transform = 'scale(1.5)';
            customCursor.style.borderColor = '#00d4ff';
        }
    }, true);

    document.addEventListener('mouseleave', (e) => {
        if (e.target.matches('button, .nav-link, .file-item, .tool-button')) {
            customCursor.style.transform = 'scale(1)';
            customCursor.style.borderColor = '#00ff41';
        }
    }, true);
}

// Loading Screen Implementation
function initializeLoadingScreen() {
    const loadingScreen = document.getElementById('loading-screen');
    const mainContent = document.getElementById('main-content');
    
    if (!loadingScreen || !mainContent) {
        console.error('Loading screen or main content not found');
        return;
    }
    
    // Show loading animation
    setTimeout(() => {
        loadingScreen.classList.add('fade-out');
        setTimeout(() => {
            loadingScreen.style.display = 'none';
            mainContent.classList.remove('hidden');
            initializeMainContent();
        }, 800);
    }, 4000);
}

// Initialize main content after loading
function initializeMainContent() {
    console.log('Initializing main content...');
    
    // Initialize all components
    initializeNavigation();
    initializeHeroTyping();
    initializeProjectInteractions();
    initializeInteractiveTools();
    initializeContactForm();
    addGlitchEffects();
    
    console.log('Main content initialized successfully');
}

// Navigation functionality - FIXED
function initializeNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            const targetSection = document.getElementById(targetId);
            
            console.log('Navigating to:', targetId, targetSection);
            
            if (targetSection) {
                // Remove active class from all links
                navLinks.forEach(l => l.classList.remove('active'));
                // Add active class to clicked link
                this.classList.add('active');
                
                // Smooth scroll
                targetSection.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            } else {
                console.error('Target section not found:', targetId);
            }
        });
    });
    
    // Update active nav on scroll
    window.addEventListener('scroll', updateActiveNavigation);
}

function updateActiveNavigation() {
    const sections = document.querySelectorAll('section');
    const navLinks = document.querySelectorAll('.nav-link');
    
    let currentSection = '';
    
    sections.forEach(section => {
        const sectionTop = section.offsetTop - 100;
        const sectionHeight = section.clientHeight;
        
        if (window.scrollY >= sectionTop && window.scrollY < sectionTop + sectionHeight) {
            currentSection = section.getAttribute('id');
        }
    });
    
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href').substring(1) === currentSection) {
            link.classList.add('active');
        }
    });
}

// Hero section typing animation
function initializeHeroTyping() {
    const typingText = document.querySelector('.typing-text');
    
    if (!typingText) {
        console.warn('Typing text element not found');
        return;
    }
    
    const commands = [
        'run_security_scan.sh',
        'nmap -sS target_network',
        'analyze_threat_intelligence', 
        'hunt_advanced_persistents',
        'monitor_network_traffic',
        'investigate_incidents'
    ];
    
    let commandIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    
    function typeCommand() {
        const currentCommand = commands[commandIndex];
        
        if (!isDeleting) {
            typingText.textContent = currentCommand.substring(0, charIndex + 1);
            charIndex++;
            
            if (charIndex === currentCommand.length) {
                setTimeout(() => { isDeleting = true; }, 2000);
                return;
            }
        } else {
            typingText.textContent = currentCommand.substring(0, charIndex - 1);
            charIndex--;
            
            if (charIndex === 0) {
                isDeleting = false;
                commandIndex = (commandIndex + 1) % commands.length;
            }
        }
        
        const typingSpeed = isDeleting ? 50 : 100;
        setTimeout(typeCommand, typingSpeed);
    }
    
    setTimeout(typeCommand, 1000);
}

// Project interactions - FIXED
function initializeProjectInteractions() {
    const fileItems = document.querySelectorAll('.file-item');
    const projectDetails = document.querySelector('.project-details');
    const selectedFile = document.querySelector('.selected-file');
    const projectInfo = document.querySelector('.project-info');
    
    if (!fileItems.length || !projectDetails || !selectedFile || !projectInfo) {
        console.warn('Project elements not found:', {
            fileItems: fileItems.length,
            projectDetails: !!projectDetails,
            selectedFile: !!selectedFile,
            projectInfo: !!projectInfo
        });
        return;
    }
    
    fileItems.forEach(item => {
        item.addEventListener('click', function() {
            const projectIndex = parseInt(this.getAttribute('data-project'));
            const project = projectsData[projectIndex];
            
            if (!project) {
                console.error('Project not found at index:', projectIndex);
                return;
            }
            
            // Update selected file name
            selectedFile.textContent = project.filename;
            
            // Update project info
            projectInfo.innerHTML = `
                <div style="color: #00ff41; margin-bottom: 1rem;">
                    <strong>${project.title}</strong>
                </div>
                <div style="color: #ffffff; margin-bottom: 1rem;">
                    ${project.description}
                </div>
                <div style="color: #00d4ff; margin-bottom: 1rem;">
                    <strong>Tools:</strong> ${project.tools.join(', ')}
                </div>
                <div style="color: #00ff41; margin-bottom: 1rem;">
                    <strong>Impact:</strong> ${project.impact}
                </div>
                <pre style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 3px; overflow-x: auto; color: #ffffff; font-size: 0.85rem;">${project.details}</pre>
            `;
            
            // Show project details
            projectDetails.classList.remove('hidden');
            
            // Add selection effect
            fileItems.forEach(f => f.style.background = '');
            this.style.background = 'rgba(0, 255, 65, 0.2)';
        });
    });
}

// Interactive tools functionality - FIXED
function initializeInteractiveTools() {
    const toolButtons = document.querySelectorAll('.tool-button');
    const toolInterface = document.getElementById('tool-interface');
    
    if (!toolButtons.length || !toolInterface) {
        console.warn('Interactive tools elements not found:', {
            toolButtons: toolButtons.length,
            toolInterface: !!toolInterface
        });
        return;
    }
    
    toolButtons.forEach(button => {
        button.addEventListener('click', function() {
            const toolType = this.getAttribute('data-tool');
            const tool = interactiveTools[toolType];
            
            if (!tool) {
                console.error('Tool not found:', toolType);
                return;
            }
            
            // Remove active class from all buttons
            toolButtons.forEach(btn => btn.classList.remove('active'));
            // Add active class to clicked button
            this.classList.add('active');
            
            // Update tool interface
            toolInterface.innerHTML = tool.interface;
            toolInterface.classList.remove('hidden');
        });
    });
}

// Interactive tool execution functions - WORKING
function executeIpScan() {
    const target = document.getElementById('ip-target');
    const output = document.getElementById('ip-scan-output');
    
    if (!target || !output) return;
    
    const targetValue = target.value;
    
    if (!targetValue) {
        alert('Please enter a target IP address');
        return;
    }
    
    output.style.display = 'block';
    output.innerHTML = '[*] Scanning ' + targetValue + '...\n';
    
    // Simulate scanning process
    setTimeout(() => {
        output.innerHTML += `[+] Host is up (0.001s latency)
[+] OS Detection: Linux 5.4.0-74-generic
[+] Open ports found:
    22/tcp   open  ssh     OpenSSH 8.2p1
    80/tcp   open  http    Apache httpd 2.4.41
    443/tcp  open  https   Apache httpd 2.4.41
[+] Geolocation: ${getRandomLocation()}
[+] ISP: Fictional Internet Provider
[✓] Scan completed in 2.34 seconds

[!] Disclaimer: This is a simulated scan for portfolio demonstration`;
    }, 2000);
}

function executePortScan() {
    const target = document.getElementById('port-target');
    const output = document.getElementById('port-scan-output');
    
    if (!target || !output) return;
    
    const targetValue = target.value;
    
    if (!targetValue) {
        alert('Please enter a target IP address');
        return;
    }
    
    output.style.display = 'block';
    output.innerHTML = '[*] Port scanning ' + targetValue + '...\n';
    
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306];
    let currentPort = 0;
    
    const scanInterval = setInterval(() => {
        if (currentPort < commonPorts.length) {
            const port = commonPorts[currentPort];
            const status = Math.random() > 0.7 ? 'open' : 'closed';
            const service = getServiceName(port);
            
            if (status === 'open') {
                output.innerHTML += `[+] ${port}/tcp  ${status}  ${service}\n`;
            }
            
            currentPort++;
        } else {
            clearInterval(scanInterval);
            output.innerHTML += '\n[✓] Port scan completed\n[!] Disclaimer: Simulated scan for portfolio demonstration';
        }
    }, 200);
}

function executeHashCrack() {
    const hashInput = document.getElementById('hash-input');
    const output = document.getElementById('hash-crack-output');
    
    if (!hashInput || !output) return;
    
    const hash = hashInput.value;
    
    if (!hash) {
        alert('Please enter a hash to crack');
        return;
    }
    
    output.style.display = 'block';
    output.innerHTML = '[*] Analyzing hash: ' + hash + '\n';
    
    setTimeout(() => {
        const hashTypes = ['MD5', 'SHA1', 'SHA256', 'NTLM'];
        const randomType = hashTypes[Math.floor(Math.random() * hashTypes.length)];
        
        output.innerHTML += `[+] Hash type detected: ${randomType}
[*] Consulting rainbow tables...
[*] Trying wordlist attack...
[*] Attempting brute force...
`;
        
        setTimeout(() => {
            if (hash.toLowerCase() === '5d41402abc4b2a76b9719d911017c592') {
                output.innerHTML += '[✓] Hash cracked: "hello"\n';
            } else {
                output.innerHTML += '[+] Hash cracked: "' + generateRandomPassword() + '"\n';
            }
            output.innerHTML += '[*] Crack time: 0.34 seconds\n[!] Disclaimer: Simulated cracking for demonstration';
        }, 2000);
    }, 1000);
}

function executePingSweep() {
    const target = document.getElementById('ping-target');
    const output = document.getElementById('ping-sweep-output');
    
    if (!target || !output) return;
    
    const network = target.value;
    
    if (!network) {
        alert('Please enter a network range');
        return;
    }
    
    output.style.display = 'block';
    output.innerHTML = '[*] Ping sweep on ' + network + '...\n';
    
    const baseIp = network.split('/')[0].split('.').slice(0, 3).join('.');
    
    setTimeout(() => {
        for (let i = 1; i <= 10; i++) {
            const ip = baseIp + '.' + i;
            const status = Math.random() > 0.6 ? 'UP' : 'DOWN';
            if (status === 'UP') {
                const latency = (Math.random() * 10 + 1).toFixed(2);
                output.innerHTML += `[+] ${ip} is UP (${latency}ms)\n`;
            }
        }
        output.innerHTML += '\n[✓] Ping sweep completed\n[!] Disclaimer: Simulated ping for demonstration';
    }, 1500);
}

function executePacketSniff() {
    const interfaceSelect = document.getElementById('interface-select');
    const output = document.getElementById('packet-sniff-output');
    
    if (!interfaceSelect || !output) return;
    
    const interface_name = interfaceSelect.value;
    
    output.style.display = 'block';
    output.innerHTML = '[*] Starting packet capture on ' + interface_name + '...\n';
    
    const packets = [
        'TCP 192.168.1.100:3847 → 172.217.164.110:443 [SYN] Seq=0',
        'TCP 172.217.164.110:443 → 192.168.1.100:3847 [SYN, ACK] Seq=0 Ack=1',
        'HTTP GET /api/data HTTP/1.1 Host: api.example.com',
        'DNS 192.168.1.100 → 8.8.8.8 Standard query A google.com',
        'HTTPS TLS Client Hello → 173.252.74.22:443',
        'TCP 192.168.1.150:22 → 192.168.1.100:34567 [PSH, ACK]'
    ];
    
    let packetCount = 0;
    const sniffInterval = setInterval(() => {
        if (packetCount < 20) {
            const randomPacket = packets[Math.floor(Math.random() * packets.length)];
            const timestamp = new Date().toLocaleTimeString();
            output.innerHTML += `[${timestamp}] ${randomPacket}\n`;
            packetCount++;
        } else {
            clearInterval(sniffInterval);
            output.innerHTML += '\n[✓] Packet capture stopped\n[!] Disclaimer: Simulated traffic for demonstration';
        }
    }, 500);
}

// Utility functions for interactive tools
function getRandomLocation() {
    const locations = ['San Francisco, CA', 'New York, NY', 'London, UK', 'Tokyo, JP', 'Sydney, AU'];
    return locations[Math.floor(Math.random() * locations.length)];
}

function getServiceName(port) {
    const services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 993: 'imaps',
        995: 'pop3s', 3389: 'rdp', 5432: 'postgresql', 3306: 'mysql'
    };
    return services[port] || 'unknown';
}

function generateRandomPassword() {
    const passwords = ['password123', 'admin', 'letmein', 'welcome', 'qwerty123', 'secret'];
    return passwords[Math.floor(Math.random() * passwords.length)];
}

// Contact form handling - FIXED
function initializeContactForm() {
    const contactForm = document.getElementById('contact-form');
    
    if (!contactForm) {
        console.warn('Contact form not found');
        return;
    }
    
    contactForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const name = document.getElementById('name')?.value || '';
        const email = document.getElementById('email')?.value || '';
        const message = document.getElementById('message')?.value || '';
        
        const submitButton = contactForm.querySelector('.terminal-submit');
        
        if (!submitButton) {
            console.error('Submit button not found');
            return;
        }
        
        const originalText = submitButton.textContent;
        
        submitButton.textContent = '$ sending_message.sh...';
        submitButton.disabled = true;
        
        // Simulate sending
        setTimeout(() => {
            alert(`[✓] Message transmitted successfully!\n\nFrom: ${name}\nEmail: ${email}\n\nI'll decrypt your message and respond via encrypted channel within 24 hours.\n\nStay secure! - HACKR.DEV`);
            
            contactForm.reset();
            submitButton.textContent = originalText;
            submitButton.disabled = false;
        }, 2000);
    });
}

// Add random glitch effects
function addGlitchEffects() {
    const glitchElements = document.querySelectorAll('.hero-title');
    
    setInterval(() => {
        glitchElements.forEach(element => {
            if (Math.random() > 0.95) {
                element.style.animation = 'none';
                setTimeout(() => {
                    element.style.animation = 'glitch 2s infinite';
                }, 100);
            }
        });
    }, 3000);
}

// Matrix rain effect for background
function createMatrixRain() {
    const chars = "01";
    const columns = Math.floor(window.innerWidth / 20);
    const drops = [];
    
    for (let i = 0; i < columns; i++) {
        drops[i] = 1;
    }
    
    function drawMatrix() {
        const matrixContainer = document.querySelector('.matrix-bg');
        if (!matrixContainer) return;
        
        let matrixText = '';
        
        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            matrixText += text;
            
            if (drops[i] * 20 > window.innerHeight && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
        
        if (matrixContainer) {
            matrixContainer.textContent = matrixText;
        }
    }
    
    setInterval(drawMatrix, 100);
}

// Performance optimization
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Optimize scroll events
const debouncedNavUpdate = debounce(updateActiveNavigation, 100);
window.addEventListener('scroll', debouncedNavUpdate);

// Console easter eggs
console.log(`
███████╗██████╗ ██████╗  ██████╗ ████████╗██████╗  █████╗  ██████╗███████╗
╚══███╔╝╚════██╗██╔══██╗██╔═████╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ███╔╝  █████╔╝██████╔╝██║██╔██║   ██║   ██████╔╝███████║██║     █████╗  
 ███╔╝   ╚═══██╗██╔══██╗████╔╝██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
███████╗██████╔╝██║  ██║╚██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗
╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
                                                                          

🛡️  Welcome to Z3roTrace Console
========================================

This portfolio demonstrates:
✓ Advanced cybersecurity knowledge
✓ Interactive hacking tools simulation  
✓ Terminal-based user interface
✓ Secure development practices

Commands available:
- konami(): Activate special mode
- matrix(): Toggle matrix background
- hackr.about(): Display system info

Contact: harshjagadale3211@gmail.com  
Stay secure! 🔒
`);

// Console commands
window.konami = function() {
    document.body.style.filter = 'hue-rotate(180deg) invert(0.1)';
    setTimeout(() => document.body.style.filter = '', 3000);
    console.log('🎯 Special mode activated!');
};

window.matrix = function() {
    createMatrixRain();
    console.log('🟢 Matrix background enabled');
};

window.hackr = {
    about: function() {
        console.log(`
Z3r0Trac3.sh System Information:
============================
Version: 1.0.0
Author: Cybersecurity Analyst
Framework: Vanilla JS + CSS3
Security Level: MAXIMUM
Encryption: 256-bit
Status: OPERATIONAL
        `);
    }
};

// Initialize matrix effect after content loads
setTimeout(createMatrixRain, 5000);

// Ensure initialization runs
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        console.log('DOM loaded, initializing...');
    });
} else {
    console.log('DOM already loaded, initializing immediately...');
}