// IT307 DDoS Defense System - Dashboard Client Logic

let trafficChart;
const MAX_DATA_POINTS = 25;

document.addEventListener("DOMContentLoaded", () => {
    initChart();
    fetchData();
    setInterval(fetchData, 1500);
});

function initChart() {
    const ctx = document.getElementById("trafficChart").getContext("2d");
    
    trafficChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: [],
            datasets: [
                {
                    label: "Total PPS",
                    borderColor: "#00f2fe",
                    backgroundColor: "rgba(0, 242, 254, 0.1)",
                    borderWidth: 2,
                    data: [],
                    tension: 0.35,
                    fill: true
                },
                {
                    label: "TCP/SYN",
                    borderColor: "#4facfe",
                    borderWidth: 1.5,
                    data: [],
                    tension: 0.35
                },
                {
                    label: "UDP",
                    borderColor: "#ffb703",
                    borderWidth: 1.5,
                    data: [],
                    tension: 0.35
                },
                {
                    label: "ICMP",
                    borderColor: "#ff3366",
                    borderWidth: 1.5,
                    data: [],
                    tension: 0.35
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                x: {
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: { color: "#94a3b8", maxTicksLimit: 8 }
                },
                y: {
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: { color: "#94a3b8" },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    labels: { color: "#f3f4f6", font: { size: 11 } }
                }
            }
        }
    });
}

async function fetchData() {
    try {
        await Promise.all([
            updateStats(),
            updateAlerts(),
            updateMitigations()
        ]);
    } catch (err) {
        console.error("Error fetching telemetry:", err);
    }
}

async function updateStats() {
    const res = await fetch("/api/stats");
    const data = await res.json();
    if (!data || data.length === 0) return;

    const latest = data[data.length - 1];
    
    // Update KPI cards
    document.getElementById("total-pps").innerHTML = `${Math.round(latest.total_pps)} <span class="unit">PPS</span>`;
    document.getElementById("tcp-pps").innerHTML = `${Math.round(latest.tcp_pps)} <span class="unit">PPS</span>`;
    document.getElementById("udp-pps").innerHTML = `${Math.round(latest.udp_pps + latest.icmp_pps)} <span class="unit">PPS</span>`;

    // Status Banner Logic
    const sysStatus = document.getElementById("sys-status");
    const statusDot = document.getElementById("status-dot");
    const statusText = document.getElementById("status-text");

    if (latest.total_pps > 100) {
        statusDot.className = "status-pulse red";
        statusText.textContent = "ATTACK IN PROGRESS - MITIGATION ENGAGED";
        sysStatus.style.borderColor = "rgba(255, 51, 102, 0.5)";
    } else {
        statusDot.className = "status-pulse green";
        statusText.textContent = "MONITORING NORMAL";
        sysStatus.style.borderColor = "rgba(255, 255, 255, 0.08)";
    }

    // Update Chart
    const labels = data.map(d => {
        const date = new Date(d.timestamp * 1000);
        return date.toTimeString().split(" ")[0];
    });

    trafficChart.data.labels = labels;
    trafficChart.data.datasets[0].data = data.map(d => d.total_pps);
    trafficChart.data.datasets[1].data = data.map(d => d.tcp_pps);
    trafficChart.data.datasets[2].data = data.map(d => d.udp_pps);
    trafficChart.data.datasets[3].data = data.map(d => d.icmp_pps);
    trafficChart.update();
}

async function updateAlerts() {
    const res = await fetch("/api/alerts");
    const alerts = await res.json();
    const container = document.getElementById("alerts-feed");
    const counter = document.getElementById("alert-counter");

    counter.textContent = `${alerts.length} Incidents`;

    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div class="empty-state">No active anomalies detected. System running in clean state.</div>';
        return;
    }

    container.innerHTML = alerts.map(a => {
        const timeStr = new Date(a.timestamp * 1000).toLocaleTimeString();
        return `
            <div class="alert-item ${a.severity}">
                <div class="alert-header">
                    <span>${a.attack_type} [${a.source_ip}]</span>
                    <span>${timeStr}</span>
                </div>
                <div class="alert-details">${a.details}</div>
            </div>
        `;
    }).join("");
}

async function updateMitigations() {
    const res = await fetch("/api/mitigations");
    const mitigations = await res.json();
    const tbody = document.getElementById("mitigation-table-body");
    const countVal = document.getElementById("blocked-count");
    const badge = document.getElementById("mitigation-badge");

    countVal.textContent = mitigations.length;
    badge.textContent = `${mitigations.length} Filtered`;

    if (!mitigations || mitigations.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-table">No IPs currently throttled or dropped.</td></tr>';
        return;
    }

    const now = Date.now() / 1000;
    tbody.innerHTML = mitigations.map(m => {
        const remaining = Math.max(0, Math.round(m.expires_at - now));
        return `
            <tr>
                <td><strong>${m.source_ip}</strong></td>
                <td><span class="badge" style="color: #ff3366; border-color: rgba(255, 51, 102, 0.4);">${m.action}</span></td>
                <td>${remaining > 0 ? remaining + 's' : 'Permanent'}</td>
                <td>
                    <button class="btn-unblock" onclick="unblockIp('${m.source_ip}')">Unblock</button>
                </td>
            </tr>
        `;
    }).join("");
}

async function unblockIp(ip) {
    try {
        const res = await fetch("/api/unblock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        if (data.success) {
            updateMitigations();
        }
    } catch (err) {
        console.error("Failed to unblock IP:", err);
    }
}
