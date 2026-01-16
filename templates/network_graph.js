// Network Graph Visualization using D3.js

function renderNetworkGraph(data) {
    const container = d3.select("#network-graph-container");
    const width = container.node().getBoundingClientRect().width;
    const height = 600;

    // 清空容器
    container.html("");

    // 检查数据
    if (!data || !data.nodes || data.nodes.length === 0) {
        container.append("div")
            .attr("class", "loading")
            .style("display", "flex")
            .style("justify-content", "center")
            .style("align-items", "center")
            .style("height", height + "px")
            .text("No data to display");
        return;
    }

    // 创建 SVG
    const svg = container.append("svg")
        .attr("width", width)
        .attr("height", height)
        .style("background-color", "#fafafa");

    // 添加缩放功能
    const g = svg.append("g");

    const zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on("zoom", (event) => {
            g.attr("transform", event.transform);
        });

    svg.call(zoom);

    // 创建力模拟
    const simulation = d3.forceSimulation(data.nodes)
        .force("link", d3.forceLink(data.edges)
            .id(d => d.id)
            .distance(150))
        .force("charge", d3.forceManyBody()
            .strength(-400))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(30));

    // 绘制边
    const link = g.append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(data.edges)
        .join("line")
        .attr("stroke", "#999")
        .attr("stroke-opacity", 0.6)
        .attr("stroke-width", 2);

    // 绘制边标签
    const linkLabel = g.append("g")
        .attr("class", "link-labels")
        .selectAll("text")
        .data(data.edges)
        .join("text")
        .attr("font-size", 10)
        .attr("fill", "#666")
        .attr("text-anchor", "middle")
        .text(d => d.label);

    // 绘制节点
    const node = g.append("g")
        .attr("class", "nodes")
        .selectAll("circle")
        .data(data.nodes)
        .join("circle")
        .attr("r", 12)
        .attr("fill", d => d.color)
        .attr("stroke", "#fff")
        .attr("stroke-width", 2)
        .style("cursor", "pointer")
        .call(drag(simulation));

    // 添加节点标签
    const label = g.append("g")
        .attr("class", "labels")
        .selectAll("text")
        .data(data.nodes)
        .join("text")
        .text(d => d.label)
        .attr("font-size", 11)
        .attr("dx", 15)
        .attr("dy", 4)
        .style("pointer-events", "none");

    // 添加工具提示
    const tooltip = container.append("div")
        .attr("class", "node-tooltip")
        .style("position", "absolute")
        .style("display", "none")
        .style("background", "white")
        .style("padding", "10px")
        .style("border-radius", "8px")
        .style("box-shadow", "0 4px 12px rgba(0,0,0,0.2)")
        .style("pointer-events", "none");

    // 节点点击事件
    node.on("click", (event, d) => {
        event.stopPropagation();
        showNodeDetails(d);
    });

    // 节点悬停事件
    node.on("mouseover", (event, d) => {
        tooltip.style("display", "block")
            .html(createTooltipContent(d));
    })
    .on("mousemove", (event) => {
        tooltip.style("left", (event.pageX + 10) + "px")
            .style("top", (event.pageY - 10) + "px");
    })
    .on("mouseout", () => {
        tooltip.style("display", "none");
    });

    // 更新位置
    simulation.on("tick", () => {
        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        linkLabel
            .attr("x", d => (d.source.x + d.target.x) / 2)
            .attr("y", d => (d.source.y + d.target.y) / 2);

        node
            .attr("cx", d => d.x)
            .attr("cy", d => d.y);

        label
            .attr("x", d => d.x)
            .attr("y", d => d.y);
    });

    // 拖拽功能
    function drag(simulation) {
        function dragstarted(event) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }

        function dragged(event) {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }

        function dragended(event) {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }

        return d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended);
    }

    // 创建工具提示内容
    function createTooltipContent(d) {
        let content = `<strong>${d.type.toUpperCase()}</strong><br>`;
        content += `<strong>${d.label}</strong><br>`;

        if (d.type === 'alb') {
            const hasWaf = d.details.has_waf ? 'Yes 🛡️' : 'No ⚠️';
            content += `Has WAF: ${hasWaf}<br>`;
            content += `Scheme: ${d.details.scheme || 'N/A'}`;
        } else if (d.type === 'waf') {
            content += `Scope: ${d.details.scope || 'N/A'}<br>`;
            content += `Region: ${d.details.region || 'N/A'}`;
        } else if (d.type === 'dns') {
            content += `Type: ${d.details.type || 'N/A'}<br>`;
            content += `Zone: ${d.details.zone || 'N/A'}`;
        }

        return content;
    }

    // 显示节点详情（点击时）
    function showNodeDetails(d) {
        const details = JSON.stringify(d.details, null, 2);
        alert(`${d.type.toUpperCase()}: ${d.label}\n\nDetails:\n${details}`);
    }

    // 添加图例
    addLegend(container);
}

// 添加图例
function addLegend(container) {
    const legend = container.append("div")
        .attr("class", "legend")
        .style("margin-top", "1rem")
        .style("padding", "1rem")
        .style("background-color", "#f9f9f9")
        .style("border-radius", "4px")
        .style("display", "flex")
        .style("flex-wrap", "wrap")
        .style("gap", "1rem");

    const legendData = [
        { color: "#4CAF50", label: "DNS Record" },
        { color: "#2196F3", label: "ALB (Protected)" },
        { color: "#F44336", label: "ALB (Unprotected Public)" },
        { color: "#FFC107", label: "ALB (Internal)" },
        { color: "#FF9800", label: "WAF ACL" }
    ];

    legendData.forEach(item => {
        const legendItem = legend.append("div")
            .style("display", "flex")
            .style("align-items", "center")
            .style("gap", "0.5rem");

        legendItem.append("div")
            .style("width", "20px")
            .style("height", "20px")
            .style("border-radius", "50%")
            .style("background-color", item.color);

        legendItem.append("span")
            .text(item.label);
    });
}