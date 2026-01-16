// Dashboard Charts using Chart.js

function renderDashboard(data) {
    if (!data) {
        console.error("Dashboard data is not available");
        return;
    }

    // WAF 覆盖率饼图
    renderWAFCoverageChart(data.waf_coverage);

    // 按账户统计柱状图
    if (data.by_account && data.by_account.length > 0) {
        renderByAccountChart(data.by_account);
    }

    // 按区域统计柱状图
    if (data.by_region && data.by_region.length > 0) {
        renderByRegionChart(data.by_region);
    }

    // 添加摘要卡片
    renderSummaryCards(data.summary);
}

// WAF 覆盖率饼图
function renderWAFCoverageChart(coverageData) {
    const ctx = document.getElementById('waf-coverage-chart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Protected', 'Unprotected'],
            datasets: [{
                data: [
                    coverageData.protected || 0,
                    coverageData.unprotected || 0
                ],
                backgroundColor: ['#4CAF50', '#F44336'],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: `WAF Coverage: ${coverageData.coverage_rate || 0}%`,
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                },
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// 按账户统计柱状图
function renderByAccountChart(accountData) {
    const ctx = document.getElementById('by-account-chart');
    if (!ctx) return;

    // 限制显示前 10 个账户
    const limitedData = accountData.slice(0, 10);

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: limitedData.map(a => a.account_id.substring(0, 12) + '...'),
            datasets: [
                {
                    label: 'ALBs',
                    data: limitedData.map(a => a.alb_count),
                    backgroundColor: '#2196F3'
                },
                {
                    label: 'WAF ACLs',
                    data: limitedData.map(a => a.waf_count),
                    backgroundColor: '#FF9800'
                },
                {
                    label: 'DNS Records',
                    data: limitedData.map(a => a.dns_count),
                    backgroundColor: '#4CAF50'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Resources by Account',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                },
                legend: {
                    position: 'bottom'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

// 按区域统计柱状图
function renderByRegionChart(regionData) {
    const ctx = document.getElementById('by-region-chart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: regionData.map(r => r.region),
            datasets: [
                {
                    label: 'ALBs',
                    data: regionData.map(r => r.alb_count),
                    backgroundColor: '#2196F3'
                },
                {
                    label: 'WAF ACLs',
                    data: regionData.map(r => r.waf_count),
                    backgroundColor: '#FF9800'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Resources by Region',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                },
                legend: {
                    position: 'bottom'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

// 渲染摘要卡片
function renderSummaryCards(summaryData) {
    if (!summaryData) return;

    const container = document.getElementById('summary-cards');
    if (!container) return;

    const cards = [
        {
            title: summaryData.total_albs || 0,
            label: 'Total ALBs'
        },
        {
            title: summaryData.total_wafs || 0,
            label: 'Total WAF ACLs'
        },
        {
            title: summaryData.total_dns_records || 0,
            label: 'DNS Records'
        }
    ];

    cards.forEach(card => {
        const cardDiv = document.createElement('div');
        cardDiv.className = 'summary-card';
        cardDiv.innerHTML = `
            <h3>${card.title}</h3>
            <p>${card.label}</p>
        `;
        container.appendChild(cardDiv);
    });
}