document.addEventListener('DOMContentLoaded', () => {
    // Only execute if on dashboard
    if (!document.getElementById('packet-table')) return;

    // --- Socket.IO Setup ---
    const socket = io();
    let isSniffing = false;
    let currentFilter = 'all';

    // --- DOM Elements ---
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');
    const btnClear = document.getElementById('btn-clear');
    const ifaceSelect = document.getElementById('iface-select');
    const liveIndicator = document.querySelector('.live-indicator');
    const packetBody = document.getElementById('packet-body');
    const alertsFeed = document.getElementById('alerts-feed');
    const packetSearch = document.getElementById('packet-search');
    const packetCount = document.getElementById('packet-count');

    // Stats Elements
    const statTotal = document.getElementById('stat-total');
    const statTcp = document.getElementById('stat-tcp');
    const statUdp = document.getElementById('stat-udp');
    const statHttp = document.getElementById('stat-http');
    const statHttps = document.getElementById('stat-https');
    const statBandwidth = document.getElementById('stat-bandwidth');

    // --- Chart.js Setup ---
    // 1. Protocol Doughnut Chart
    const ctx = document.getElementById('protocolChart');
    let protocolChart = null;
    if (ctx) {
        try {
            protocolChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: [
                            '#26749b',
                            '#25834f',
                            '#a96713',
                            '#8a9690'
                        ],
                        borderColor: '#ffffff',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '70%',
                    plugins: {
                        legend: { position: 'bottom', labels: { color: '#64736d', padding: 10, font: { size: 10 } } }
                    }
                }
            });
        } catch (e) { console.error("Protocol Chart failed:", e); }
    }

    // 2. Traffic Rate Line Chart
    const ctxTraffic = document.getElementById('trafficChart');
    let trafficChart = null;
    if (ctxTraffic) {
        try {
            trafficChart = new Chart(ctxTraffic, {
                type: 'line',
                data: {
                    labels: Array(15).fill(''),
                    datasets: [{
                        label: 'Packets / sec',
                        data: Array(15).fill(0),
                        borderColor: '#087f72',
                        backgroundColor: 'rgba(8, 127, 114, 0.12)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { display: false },
                        y: { ticks: { color: '#64736d', font: { size: 10 } }, grid: { color: 'rgba(32, 44, 40, 0.1)' }, beginAtZero: true }
                    }
                }
            });
        } catch (e) { console.error("Traffic Chart failed:", e); }
    }

    // --- Helper Functions ---
    const formatBytes = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const getProtocolBadgeClass = (proto) => {
        const p = proto.toUpperCase();
        if (p === 'TCP') return 'badge-tcp';
        if (p === 'UDP') return 'badge-udp';
        if (p === 'ICMP') return 'badge-icmp';
        return 'badge-tcp'; // Default
    };

    const applyPacketFilters = () => {
        const query = packetSearch?.value.trim().toLowerCase() || '';
        const rows = packetBody.querySelectorAll('tr[data-packet]');
        let visibleCount = 0;

        rows.forEach(row => {
            const packet = JSON.parse(row.dataset.packet || '{}');
            const protocolMatches = currentFilter === 'all' || packet.protocol === currentFilter;
            const searchableText = [
                packet.timestamp, packet.protocol, packet.src_ip, packet.src_port,
                packet.dst_ip, packet.dst_port, packet.length, packet.summary
            ].join(' ').toLowerCase();
            const queryMatches = !query || searchableText.includes(query);

            row.hidden = !(protocolMatches && queryMatches);
            if (!row.hidden) visibleCount++;
        });

        let emptyRow = packetBody.querySelector('.filter-empty-state');
        if (rows.length > 0 && visibleCount === 0) {
            if (!emptyRow) {
                emptyRow = document.createElement('tr');
                emptyRow.className = 'filter-empty-state';
                const cell = document.createElement('td');
                cell.colSpan = 6;
                cell.textContent = 'No packets match the current search and protocol filter.';
                emptyRow.appendChild(cell);
                packetBody.appendChild(emptyRow);
            }
        } else if (emptyRow) {
            emptyRow.remove();
        }

        if (packetCount) packetCount.textContent = `${visibleCount} of ${rows.length} packets`;
    };

    packetSearch?.addEventListener('input', applyPacketFilters);

    // --- Socket Event Handlers ---

    socket.on('connect', () => {
        console.log('Connected to WebSocket server');
        // Initial state is fetched via the status_update emitted on connect
    });

    socket.on('status_update', (data) => {
        isSniffing = data.sniffer_running;
        
        // Update UI Controls & Sidebar Engine Status Card
        const statusDot = document.querySelector('.status-dot');
        const statusTitle = document.querySelector('.status-title');
        const statusMode = document.getElementById('status-mode');
        
        if (isSniffing) {
            btnStart.disabled = true;
            btnStop.disabled = false;
            ifaceSelect.disabled = true;
            liveIndicator.classList.add('active');
            
            // Sidebar Dynamic Card
            if (statusDot) statusDot.className = 'status-dot green';
            if (statusTitle) statusTitle.textContent = 'ENGINE ACTIVE';
            if (statusMode) statusMode.textContent = 'Promiscuous';
            
            // Apply glow effect when running
            document.querySelectorAll('.stat-card').forEach(c => c.classList.add('pulse-glow'));
        } else {
            btnStart.disabled = false;
            btnStop.disabled = true;
            ifaceSelect.disabled = false;
            liveIndicator.classList.remove('active');

            // Sidebar Dynamic Card
            if (statusDot) statusDot.className = 'status-dot red';
            if (statusTitle) statusTitle.textContent = 'ENGINE STANDBY';
            if (statusMode) statusMode.textContent = 'Idle';

            document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('pulse-glow'));
        }

        // Update Stats
        if (data.stats) {
            statTotal.textContent = data.stats.total.toLocaleString();
            statTcp.textContent = data.stats.tcp.toLocaleString();
            statUdp.textContent = data.stats.udp.toLocaleString();
            statHttp.textContent = data.stats.http.toLocaleString();
            statHttps.textContent = data.stats.https.toLocaleString();
            statBandwidth.textContent = formatBytes(data.stats.bandwidth);

            // CPU & RAM
            const statCpu = document.getElementById('stat-cpu');
            const statRam = document.getElementById('stat-ram');
            if (statCpu) statCpu.textContent = `${data.stats.cpu || 0}%`;
            if (statRam) statRam.textContent = `${data.stats.ram || 0}%`;

            // Speed & Throughput
            const speedRx = document.getElementById('speed-rx');
            const speedTx = document.getElementById('speed-tx');
            const speedAvg = document.getElementById('speed-avg');
            if (speedRx) speedRx.textContent = `${data.stats.rx_speed || 0} KB/s`;
            if (speedTx) speedTx.textContent = `${data.stats.tx_speed || 0} KB/s`;
            if (speedAvg) speedAvg.textContent = `${data.stats.avg_frame_size || 0} B`;

            // Port Radar Progress Bars
            if (data.stats.port_counts) {
                const totalP = (data.stats.port_counts['443'] + data.stats.port_counts['80'] + data.stats.port_counts['53'] + data.stats.port_counts['other']) || 1;
                const p443 = document.getElementById('p-443-val');
                const p443Bar = document.getElementById('p-443-bar');
                if (p443) p443.textContent = data.stats.port_counts['443'];
                if (p443Bar) p443Bar.style.width = `${Math.min(100, Math.round((data.stats.port_counts['443'] / totalP) * 100))}%`;

                const p80 = document.getElementById('p-80-val');
                const p80Bar = document.getElementById('p-80-bar');
                if (p80) p80.textContent = data.stats.port_counts['80'];
                if (p80Bar) p80Bar.style.width = `${Math.min(100, Math.round((data.stats.port_counts['80'] / totalP) * 100))}%`;

                const p53 = document.getElementById('p-53-val');
                const p53Bar = document.getElementById('p-53-bar');
                if (p53) p53.textContent = data.stats.port_counts['53'];
                if (p53Bar) p53Bar.style.width = `${Math.min(100, Math.round((data.stats.port_counts['53'] / totalP) * 100))}%`;
            }

            // Update Protocol Chart
            if (protocolChart) {
                const other = data.stats.total - (data.stats.tcp + data.stats.udp + data.stats.icmp);
                protocolChart.data.datasets[0].data = [
                    data.stats.tcp,
                    data.stats.udp,
                    data.stats.icmp,
                    other > 0 ? other : 0
                ];
                protocolChart.update();
            }

            // Update Traffic Line Chart
            if (trafficChart && data.stats.rate_history) {
                trafficChart.data.datasets[0].data = data.stats.rate_history;
                trafficChart.update();
            }

            // Update Top IP Talkers List
            const topIpsList = document.getElementById('top-ips-list');
            if (topIpsList && data.stats.top_ips) {
                if (data.stats.top_ips.length === 0) {
                    topIpsList.innerHTML = `<p class="text-muted" style="text-align: center; font-size: 0.85rem;">Waiting for traffic...</p>`;
                } else {
                    topIpsList.innerHTML = data.stats.top_ips.map(item => `
                        <div class="top-ip-row">
                            <span class="top-ip-address">${item.ip}</span>
                            <span class="top-ip-count">${item.count} pkts</span>
                        </div>
                    `).join('');
                }
            }
        }
    });

    socket.on('new_packet', (packet) => {
        // Remove empty state if present
        const emptyState = packetBody.querySelector('.empty-state');
        if (emptyState) emptyState.remove();

        const tr = document.createElement('tr');
        tr.className = 'new-row';
        tr.dataset.packet = JSON.stringify(packet);
        
        tr.innerHTML = `
            <td>${packet.timestamp.split(' ')[1]}</td>
            <td><span class="badge ${getProtocolBadgeClass(packet.protocol)}">${packet.protocol}</span></td>
            <td>${packet.src_ip}${packet.src_port && packet.src_port !== '-' ? ':'+packet.src_port : ''}</td>
            <td>${packet.dst_ip}${packet.dst_port && packet.dst_port !== '-' ? ':'+packet.dst_port : ''}</td>
            <td>${packet.length}</td>
            <td class="text-truncate" style="max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${packet.summary}">
                ${packet.summary}
            </td>
        `;

        // Prepend to top
        packetBody.insertBefore(tr, packetBody.firstChild);

        // Keep only last 100 rows to prevent DOM lag
        if (packetBody.children.length > 100) {
            packetBody.removeChild(packetBody.lastChild);
        }
        applyPacketFilters();
    });

    socket.on('new_alert', (alert) => {
        const emptyState = alertsFeed.querySelector('.empty-alert');
        if (emptyState) emptyState.remove();

        const div = document.createElement('div');
        div.className = `alert-item ${alert.severity.toLowerCase()}`;
        div.innerHTML = `
            <div class="alert-header">
                <div class="alert-title"><i class="fas fa-exclamation-triangle"></i> ${alert.alert_type}</div>
                <div class="alert-time">${alert.timestamp.split(' ')[1]}</div>
            </div>
            <div class="alert-desc">${alert.description}</div>
            <div class="alert-src">Target: ${alert.src_ip}</div>
        `;

        alertsFeed.insertBefore(div, alertsFeed.firstChild);
    });

    // --- Control Actions ---

    btnStart.addEventListener('click', async () => {
        const iface = ifaceSelect.value;
        try {
            await fetch('/api/control/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: iface })
            });
        } catch (e) { console.error("Error starting sniffer", e); }
    });

    btnStop.addEventListener('click', async () => {
        try {
            await fetch('/api/control/stop', { method: 'POST' });
        } catch (e) { console.error("Error stopping sniffer", e); }
    });

    btnClear.addEventListener('click', async () => {
        if(confirm("Are you sure you want to clear all logged data?")) {
            try {
                await fetch('/api/control/clear', { method: 'POST' });
                packetBody.innerHTML = `
                    <tr class="empty-state">
                        <td colspan="6">
                            <div class="empty-content">
                                <i class="fas fa-inbox"></i>
                                <p>Data cleared. Waiting for new packets...</p>
                            </div>
                        </td>
                    </tr>
                `;
                alertsFeed.innerHTML = `
                    <div class="empty-alert">
                        <i class="fas fa-check-circle"></i>
                        <p>No alerts recorded.</p>
                    </div>
                `;
            } catch (e) { console.error("Error clearing data", e); }
        }
    });

    // --- Export Actions ---
    document.getElementById('btn-export-csv')?.addEventListener('click', () => {
        window.location.href = '/api/export/csv';
    });
    
    document.getElementById('btn-export-json')?.addEventListener('click', () => {
        window.location.href = '/api/export/json';
    });
    
    // Auto remove toasts after 5 seconds
    setTimeout(() => {
        document.querySelectorAll('.toast').forEach(t => {
            t.style.animation = 'slideInRight 0.3s ease reverse forwards';
            setTimeout(() => t.remove(), 300);
        });
    }, 5000);

    // --- Sidebar Protocol Filter Logic ---
    const filterMenu = document.querySelector('.filter-menu');

    if (filterMenu) {
        filterMenu.addEventListener('click', (e) => {
            const li = e.target.closest('li');
            if (!li) return;

            filterMenu.querySelectorAll('li').forEach(item => item.classList.remove('active'));
            li.classList.add('active');

            currentFilter = li.dataset.filter || 'all';
            applyPacketFilters();
        });
    }

    // --- Operations Navigation Smooth Scroll & Highlight ---
    document.querySelectorAll('.nav-scroll').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href');
            const targetEl = document.querySelector(targetId);
            if (targetEl) {
                const panel = targetEl.closest('.panel') || targetEl;
                panel.scrollIntoView({ behavior: 'smooth', block: 'center' });
                panel.classList.add('panel-highlight');
                setTimeout(() => panel.classList.remove('panel-highlight'), 1500);
            }
        });
    });
    const modal = document.getElementById('packetModal');
    const modalClose = document.getElementById('modal-close');

    if (packetBody && modal) {
        packetBody.addEventListener('click', (e) => {
            const row = e.target.closest('tr');
            if (!row || row.classList.contains('empty-state')) return;

            try {
                const packet = JSON.parse(row.dataset.packet);
                document.getElementById('m-time').textContent = packet.timestamp;
                document.getElementById('m-proto').textContent = packet.protocol;
                document.getElementById('m-src').textContent = `${packet.src_ip}:${packet.src_port || '-'}`;
                document.getElementById('m-dst').textContent = `${packet.dst_ip}:${packet.dst_port || '-'}`;
                document.getElementById('m-len').textContent = `${packet.length} Bytes`;
                document.getElementById('m-ttl').textContent = packet.ttl || 'N/A';
                document.getElementById('m-flags').textContent = packet.flags || '-';
                document.getElementById('m-summary').textContent = packet.summary;

                const hexPre = document.getElementById('m-hex');
                if (packet.hex || packet.ascii) {
                    hexPre.textContent = `HEX VIEW:\n${packet.hex || 'N/A'}\n\nASCII VIEW:\n${packet.ascii || 'N/A'}`;
                } else {
                    hexPre.textContent = "No raw payload data captured for this packet frame.";
                }

                modal.style.display = 'flex';
            } catch (err) { console.error("Error opening modal", err); }
        });

        modalClose?.addEventListener('click', () => { modal.style.display = 'none'; });
        modal.addEventListener('click', (e) => { if (e.target === modal) modal.style.display = 'none'; });
    }

    // Fetch historical logs on page load
    async function fetchInitialLogs() {
        try {
            const res = await fetch('/api/packets');
            if (res.ok) {
                const data = await res.json();
                if (data.length > 0) {
                    const emptyState = packetBody.querySelector('.empty-state');
                    if (emptyState) emptyState.remove();
                    
                    const fragment = document.createDocumentFragment();
                    data.forEach(packet => {
                        const tr = document.createElement('tr');
                        tr.dataset.packet = JSON.stringify(packet);
                        tr.innerHTML = `
                            <td>${packet.timestamp.split(' ')[1]}</td>
                            <td><span class="badge ${getProtocolBadgeClass(packet.protocol)}">${packet.protocol}</span></td>
                            <td>${packet.src_ip}${packet.src_port && packet.src_port !== '-' ? ':'+packet.src_port : ''}</td>
                            <td>${packet.dst_ip}${packet.dst_port && packet.dst_port !== '-' ? ':'+packet.dst_port : ''}</td>
                            <td>${packet.length}</td>
                            <td class="text-truncate" style="max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${packet.summary}">
                                ${packet.summary}
                            </td>
                        `;
                        fragment.appendChild(tr);
                    });
                    packetBody.appendChild(fragment);
                    applyPacketFilters();
                }
            }
        } catch (e) {
            console.error("Failed to fetch initial logs", e);
        }
    }
    
    // Fetch historical threat alerts on page load
    async function fetchInitialAlerts() {
        try {
            const res = await fetch('/api/alerts');
            if (res.ok) {
                const data = await res.json();
                if (data.length > 0) {
                    const emptyState = alertsFeed.querySelector('.empty-alert');
                    if (emptyState) emptyState.remove();
                    
                    data.forEach(alert => {
                        const div = document.createElement('div');
                        div.className = `alert-item ${alert.severity.toLowerCase()}`;
                        div.innerHTML = `
                            <div class="alert-header">
                                <div class="alert-title"><i class="fas fa-exclamation-triangle"></i> ${alert.alert_type}</div>
                                <div class="alert-time">${alert.timestamp.split(' ')[1]}</div>
                            </div>
                            <div class="alert-desc">${alert.description}</div>
                            <div class="alert-src">Target: ${alert.src_ip}</div>
                        `;
                        alertsFeed.appendChild(div);
                    });
                }
            }
        } catch (e) {
            console.error("Failed to fetch initial alerts", e);
        }
    }

    fetchInitialLogs();
    fetchInitialAlerts();
});
