from __future__ import annotations

from html import escape
from typing import Any, Dict, List, Tuple


RISK_COLOR = {
    "low": "#14a46c",
    "medium": "#b88200",
    "high": "#ff8a00",
    "critical": "#d94343",
}

NODE_FILL = {
    "case": "#eef3ff",
    "step": "#ffffff",
    "sink": "#fff0f0",
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def _short(value: Any, limit: int = 26) -> str:
    text = str(value or "")

    if len(text) <= limit:
        return text

    return text[:limit] + "..."


def _node_position(index: int, total: int) -> Tuple[int, int]:
    """
    简单分层布局：
    - case 节点在左侧；
    - step 节点横向展开；
    - sink 节点放在右侧下方。
    """
    x_gap = 230
    x = 110 + index * x_gap
    y = 160

    return x, y


def _collect_visual_nodes(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    nodes = [
        node
        for node in _as_list(graph.get("nodes"))
        if isinstance(node, dict)
    ]

    existing_ids = {str(node.get("id")) for node in nodes}

    for flow in _as_list(graph.get("high_risk_flows")):
        if not isinstance(flow, dict):
            continue

        target = str(flow.get("target") or "")

        if not target.startswith("sink:"):
            continue

        if target in existing_ids:
            continue

        tool = target.split(":", 1)[1]

        nodes.append(
            {
                "id": target,
                "type": "sink",
                "tool": tool,
                "label": f"Sink: {tool}",
                "risk": str(flow.get("risk") or "high"),
            }
        )
        existing_ids.add(target)

    return nodes


def _collect_visual_edges(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    edges = [
        edge
        for edge in _as_list(graph.get("edges"))
        if isinstance(edge, dict)
    ]

    existing = {
        (str(edge.get("source")), str(edge.get("target")))
        for edge in edges
    }

    for flow in _as_list(graph.get("high_risk_flows")):
        if not isinstance(flow, dict):
            continue

        source = str(flow.get("source") or "")
        target = str(flow.get("target") or "")

        if not source or not target:
            continue

        if (source, target) in existing:
            continue

        edges.append(
            {
                "source": source,
                "target": target,
                "edge_type": "high_risk_flow",
                "labels": flow.get("labels", []),
                "risk": flow.get("risk", "high"),
            }
        )
        existing.add((source, target))

    return edges


def _build_layout(nodes: List[Dict[str, Any]]) -> Dict[str, Tuple[int, int]]:
    layout: Dict[str, Tuple[int, int]] = {}

    case_nodes = [node for node in nodes if node.get("type") == "case"]
    step_nodes = [node for node in nodes if node.get("type") == "step"]
    sink_nodes = [node for node in nodes if node.get("type") == "sink"]

    ordered = case_nodes + sorted(
        step_nodes,
        key=lambda item: int(item.get("step_id") or 0),
    )

    for index, node in enumerate(ordered):
        layout[str(node.get("id"))] = _node_position(index, len(ordered))

    if ordered:
        last_x = 110 + (len(ordered)) * 230
    else:
        last_x = 110

    for index, node in enumerate(sink_nodes):
        layout[str(node.get("id"))] = (last_x, 90 + index * 140)

    return layout


def render_security_graph_html(
    graph: Dict[str, Any],
    *,
    report_file: str = "",
    case_id: str = "",
) -> str:
    nodes = _collect_visual_nodes(graph)
    edges = _collect_visual_edges(graph)
    layout = _build_layout(nodes)

    max_x = max([x for x, _ in layout.values()] + [900]) + 170
    max_y = max([y for _, y in layout.values()] + [360]) + 140

    edge_svg_parts: List[str] = []

    for edge in edges:
        source = str(edge.get("source"))
        target = str(edge.get("target"))

        if source not in layout or target not in layout:
            continue

        x1, y1 = layout[source]
        x2, y2 = layout[target]

        risk = str(edge.get("risk") or "low")
        color = RISK_COLOR.get(risk, "#6d778c")

        labels = ", ".join(str(item) for item in _as_list(edge.get("labels")))
        label_text = _short(labels, 34)

        mid_x = (x1 + x2) // 2
        mid_y = (y1 + y2) // 2 - 10

        edge_svg_parts.append(
            f'''
            <line x1="{x1 + 85}" y1="{y1}" x2="{x2 - 85}" y2="{y2}"
                  stroke="{color}" stroke-width="3" marker-end="url(#arrow)" />
            <text x="{mid_x}" y="{mid_y}" text-anchor="middle" class="edge-label">
              {escape(label_text)}
            </text>
            '''
        )

    node_svg_parts: List[str] = []

    for node in nodes:
        node_id = str(node.get("id"))
        x, y = layout.get(node_id, (80, 80))

        node_type = str(node.get("type") or "step")
        risk = str(node.get("risk") or "low")
        decision = str(node.get("decision") or "")
        tool = str(node.get("tool") or "")
        labels = ", ".join(
            str(item)
            for item in _as_list(node.get("input_labels")) + _as_list(node.get("output_labels"))
        )

        fill = NODE_FILL.get(node_type, "#ffffff")
        border = RISK_COLOR.get(risk, "#6d778c")

        title = str(node.get("label") or node_id)
        subtitle = tool or decision or node_type
        label_line = _short(labels, 32)

        node_svg_parts.append(
            f'''
            <g>
              <rect x="{x - 85}" y="{y - 46}" width="170" height="92"
                    rx="14" fill="{fill}" stroke="{border}" stroke-width="3" />
              <text x="{x}" y="{y - 16}" text-anchor="middle" class="node-title">
                {escape(_short(title, 24))}
              </text>
              <text x="{x}" y="{y + 8}" text-anchor="middle" class="node-subtitle">
                {escape(_short(subtitle, 24))}
              </text>
              <text x="{x}" y="{y + 30}" text-anchor="middle" class="node-label">
                {escape(label_line)}
              </text>
            </g>
            '''
        )

    high_risk_flows = _as_list(graph.get("high_risk_flows"))
    summary = graph.get("summary", {})

    flow_rows = []

    for flow in high_risk_flows:
        if not isinstance(flow, dict):
            continue

        flow_rows.append(
            "<tr>"
            f"<td>{escape(str(flow.get('source')))}</td>"
            f"<td>{escape(str(flow.get('target')))}</td>"
            f"<td>{escape(str(flow.get('tool')))}</td>"
            f"<td>{escape(', '.join(str(item) for item in _as_list(flow.get('risky_labels'))))}</td>"
            f"<td>{escape(str(flow.get('decision')))}</td>"
            f"<td>{escape(str(flow.get('risk')))}</td>"
            "</tr>"
        )

    if not flow_rows:
        flow_rows.append(
            "<tr><td colspan='6' class='muted'>No high-risk flow detected.</td></tr>"
        )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>Runtime Security Graph - {escape(str(case_id or graph.get("case_id") or ""))}</title>
  <style>
    body {{
      margin: 0;
      padding: 28px;
      font-family: Arial, "Microsoft YaHei", sans-serif;
      background: #f5f7fb;
      color: #182033;
    }}
    .card {{
      background: white;
      border: 1px solid #e6eaf2;
      border-radius: 16px;
      padding: 18px;
      margin-bottom: 18px;
      box-shadow: 0 8px 22px rgba(25, 38, 70, 0.08);
    }}
    h1, h2 {{
      margin-top: 0;
    }}
    .muted {{
      color: #6d778c;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-top: 14px;
    }}
    .metric {{
      background: #f7f9ff;
      border: 1px solid #e6eaf2;
      border-radius: 12px;
      padding: 12px;
    }}
    .metric b {{
      display: block;
      font-size: 24px;
      margin-top: 6px;
    }}
    svg {{
      width: 100%;
      min-height: 420px;
      background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
      border: 1px solid #e6eaf2;
      border-radius: 14px;
    }}
    .node-title {{
      font-size: 14px;
      font-weight: 700;
      fill: #182033;
    }}
    .node-subtitle {{
      font-size: 12px;
      fill: #44516a;
    }}
    .node-label {{
      font-size: 11px;
      fill: #6d778c;
    }}
    .edge-label {{
      font-size: 11px;
      fill: #6d778c;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      border-bottom: 1px solid #e6eaf2;
      padding: 10px;
      text-align: left;
      font-size: 14px;
    }}
    th {{
      background: #eef3ff;
    }}
    .legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 10px;
      color: #44516a;
      font-size: 13px;
    }}
    .dot {{
      display: inline-block;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      margin-right: 5px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Runtime Security Graph</h1>
    <p class="muted">Case: <b>{escape(str(case_id or graph.get("case_id") or ""))}</b></p>
    <p class="muted">Report: {escape(str(report_file))}</p>
    <div class="metrics">
      <div class="metric">Nodes <b>{escape(str(summary.get("node_count", 0)))}</b></div>
      <div class="metric">Edges <b>{escape(str(summary.get("edge_count", 0)))}</b></div>
      <div class="metric">Sinks <b>{escape(str(summary.get("sink_count", 0)))}</b></div>
      <div class="metric">High-risk Flows <b>{escape(str(summary.get("high_risk_flow_count", 0)))}</b></div>
    </div>
    <div class="legend">
      <span><span class="dot" style="background:#14a46c"></span>low</span>
      <span><span class="dot" style="background:#b88200"></span>medium</span>
      <span><span class="dot" style="background:#ff8a00"></span>high</span>
      <span><span class="dot" style="background:#d94343"></span>critical</span>
    </div>
  </div>

  <div class="card">
    <h2>Graph View</h2>
    <svg viewBox="0 0 {max_x} {max_y}" role="img" aria-label="Runtime security graph">
      <defs>
        <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3"
                orient="auto" markerUnits="strokeWidth">
          <path d="M0,0 L0,6 L9,3 z" fill="#6d778c" />
        </marker>
      </defs>
      {''.join(edge_svg_parts)}
      {''.join(node_svg_parts)}
    </svg>
  </div>

  <div class="card">
    <h2>High-risk Flow Evidence</h2>
    <table>
      <thead>
        <tr>
          <th>Source</th>
          <th>Target</th>
          <th>Sink Tool</th>
          <th>Risk Labels</th>
          <th>Decision</th>
          <th>Risk</th>
        </tr>
      </thead>
      <tbody>
        {''.join(flow_rows)}
      </tbody>
    </table>
  </div>
</body>
</html>"""
