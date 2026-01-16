// Tree Diagram Visualization using D3.js

function renderTreeDiagram(data) {
    const container = d3.select("#tree-diagram-container");
    const width = 1200;
    const height = 600;

    // 清空容器
    container.html("");

    // 检查数据
    if (!data || !data.children || data.children.length === 0) {
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

    const g = svg.append("g")
        .attr("transform", "translate(50,50)");

    // 创建树布局
    const treeLayout = d3.tree()
        .size([height - 100, width - 200]);

    const root = d3.hierarchy(data);

    treeLayout(root);

    // 绘制连线
    const link = g.selectAll("path.link")
        .data(root.links())
        .join("path")
        .attr("class", "link")
        .attr("d", d3.linkHorizontal()
            .x(d => d.y)
            .y(d => d.x))
        .attr("fill", "none")
        .attr("stroke", "#ccc")
        .attr("stroke-width", 1.5);

    // 绘制节点
    const node = g.selectAll("g.node")
        .data(root.descendants())
        .join("g")
        .attr("class", "node")
        .attr("transform", d => `translate(${d.y},${d.x})`)
        .style("cursor", "pointer");

    node.append("circle")
        .attr("r", 5)
        .attr("fill", d => {
            if (d.depth === 0) return "#667eea";  // Root
            if (d.depth === 1) return "#764ba2";  // Account
            if (d.depth === 2) return "#2196F3";  // Region
            return "#4CAF50";                     // Resources
        })
        .attr("stroke", "#fff")
        .attr("stroke-width", 2);

    node.append("text")
        .attr("dx", d => d.children ? -10 : 10)
        .attr("dy", 4)
        .attr("text-anchor", d => d.children ? "end" : "start")
        .text(d => d.data.name)
        .attr("font-size", d => {
            if (d.depth === 0) return 14;
            if (d.depth === 1) return 12;
            return 11;
        })
        .attr("font-weight", d => (d.depth <= 1 ? "bold" : "normal"))
        .attr("fill", "#333");

    // 添加可折叠功能（可选实现）
    node.on("click", (event, d) => {
        if (d.children || d._children) {
            toggleChildren(d);
            update(root);
        }
    });

    // 折叠/展开子节点
    function toggleChildren(d) {
        if (d.children) {
            d._children = d.children;
            d.children = null;
        } else {
            d.children = d._children;
            d._children = null;
        }
    }

    // 更新树（用于折叠/展开）
    function update(source) {
        treeLayout(root);

        // 更新节点
        const nodes = root.descendants();
        const nodeUpdate = g.selectAll("g.node")
            .data(nodes, d => d.id || (d.id = ++nodeIdCounter));

        // 更新连线
        const links = root.links();
        const linkUpdate = g.selectAll("path.link")
            .data(links, d => d.target.id);

        // 使用过渡动画更新位置
        nodeUpdate.transition()
            .duration(500)
            .attr("transform", d => `translate(${d.y},${d.x})`);

        linkUpdate.transition()
            .duration(500)
            .attr("d", d3.linkHorizontal()
                .x(d => d.y)
                .y(d => d.x));
    }

    let nodeIdCounter = 0;
}