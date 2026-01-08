from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def _write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", encoding="ascii", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_markdown_table(title: str, rows: list[dict], fieldnames: list[str]) -> str:
    if not rows:
        return f"## {title}\n\n(no data)\n"
    header = "| " + " | ".join(fieldnames) + " |\n"
    sep = "| " + " | ".join(["---"] * len(fieldnames)) + " |\n"
    lines = [f"## {title}\n\n", header, sep]
    for row in rows:
        line = "| " + " | ".join(str(row.get(name, "")) for name in fieldnames) + " |\n"
        lines.append(line)
    lines.append("\n")
    return "".join(lines)


def _write_html_table(title: str, rows: list[dict], fieldnames: list[str]) -> str:
    if not rows:
        return f"<h2>{title}</h2><p>(no data)</p>"
    header = "".join([f"<th>{name}</th>" for name in fieldnames])
    body_rows = []
    for row in rows:
        cells = "".join([f"<td>{row.get(name, '')}</td>" for name in fieldnames])
        body_rows.append(f"<tr>{cells}</tr>")
    body = "".join(body_rows)
    return f"<h2>{title}</h2><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>"


def _write_visjs_graph(hosts: list[dict], refresh: list[dict]) -> str:
    nodes = []
    for host in hosts:
        label = host.get("ip", "unknown")
        hostname = host.get("hostname", "")
        vendor = host.get("vendor", "")
        os = host.get("os", "")
        if hostname:
            label += f"\n{hostname}"
        if vendor or os:
            label += f"\n{vendor}\n{os}"
        nodes.append({"id": host.get("ip"), "label": label, "shape": "box"})
    
    edges = []
    for r in refresh:
        edges.append({
            "from": r.get("requester"), 
            "to": r.get("target"), 
            "arrows": "to", 
            "label": f"{r.get('avg_interval',0):.1f}s"
        })
        
    html = f"""
    <html>
    <head>
        <title>Network Topology</title>
        <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
        <style type="text/css">
            #mynetwork {{
                width: 100%;
                height: 100vh;
                border: 1px solid lightgray;
            }}
        </style>
    </head>
    <body>
    <div id="mynetwork"></div>
    <script type="text/javascript">
        var nodes = new vis.DataSet({json.dumps(nodes)});
        var edges = new vis.DataSet({json.dumps(edges)});
        var container = document.getElementById('mynetwork');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
            physics: {{
                stabilization: false,
                barnesHut: {{
                    gravitationalConstant: -80000,
                    springConstant: 0.001,
                    springLength: 200
                }}
            }},
            edges: {{
                smooth: {{
                    type: "continuous"
                }}
            }}
        }};
        var network = new vis.Network(container, data, options);
    </script>
    </body>
    </html>
    """
    return html


def _write_timeline_csv(path: Path, events: list[dict]) -> None:
    buckets: dict[tuple[int, str], int] = {}
    for event in events:
        ts = event.get("ts")
        if ts is None:
            continue
        try:
            sec = int(float(ts))
        except (ValueError, TypeError):
            continue
        etype = event.get("type", "unknown")
        key = (sec, etype)
        buckets[key] = buckets.get(key, 0) + 1
    rows = [{"timestamp": k[0], "type": k[1], "count": v} for k, v in sorted(buckets.items())]
    _write_csv(path, rows, ["timestamp", "type", "count"])


def _load_jsonl(path: Path) -> list[dict]:
    events = []
    for line in path.read_text(encoding="ascii", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events


def export_report(input_path: str, fmt: str, output_path: str) -> list[str]:
    input_file = Path(input_path)
    output_file = Path(output_path)
    fmt = fmt.lower()
    outputs = []

    data: Any = None
    if input_file.suffix.lower() == ".jsonl":
        data = _load_jsonl(input_file)
    else:
        data = json.loads(input_file.read_text(encoding="ascii"))

    if isinstance(data, dict) and "hosts" in data:
        hosts = data.get("hosts", [])
        refresh = data.get("refresh_stats", [])
        if fmt == "csv":
            if output_file.is_dir():
                hosts_path = output_file / "profile_hosts.csv"
                refresh_path = output_file / "profile_refresh.csv"
            else:
                stem = output_file.with_suffix("")
                hosts_path = Path(f"{stem}_hosts.csv")
                refresh_path = Path(f"{stem}_refresh.csv")
                _write_csv(
                    hosts_path,
                    hosts,
                    ["ip", "hostname", "mac", "vendor", "os", "first_seen", "last_seen", "count"],
                )
                _write_csv(
                    refresh_path,
                    refresh,
                    ["requester", "target", "avg_interval", "samples"],
                )
                outputs.extend([str(hosts_path), str(refresh_path)])

        elif fmt == "md":
            md = []
            md.append(_write_markdown_table("Hosts", hosts, ["ip", "hostname", "mac", "vendor", "os", "count"]))
            md.append(
                _write_markdown_table(
                    "Refresh Stats", refresh, ["requester", "target", "avg_interval", "samples"]
                )
            )
            output_file.write_text("".join(md), encoding="ascii")
            outputs.append(str(output_file))
            return outputs

        elif fmt == "html":
            html = []
            html.append("<html><head><meta charset='utf-8'><title>ARP Profile</title>")
            html.append("<style>body{font-family:Arial,sans-serif}table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:4px 8px}</style>")
            html.append("</head><body>")
            html.append(_write_html_table("Hosts", hosts, ["ip", "hostname", "mac", "vendor", "os", "count"]))
            html.append(
                _write_html_table(
                    "Refresh Stats", refresh, ["requester", "target", "avg_interval", "samples"]
                )
            )
            html.append("</body></html>")
            output_file.write_text("".join(html), encoding="ascii")
            outputs.append(str(output_file))
            return outputs

        elif fmt == "graph":
            html = _write_visjs_graph(hosts, refresh)
            output_file.write_text(html, encoding="ascii")
            outputs.append(str(output_file))
            return outputs

    if isinstance(data, list):
        events = data
    elif isinstance(data, dict) and "events" in data:
        events = data.get("events", [])
    else:
        events = []

    if fmt == "csv":
        fieldnames = [
            "type",
            "ip",
            "mac",
            "old_mac",
            "new_mac",
            "count",
            "window",
            "ts",
            "src_ip",
            "dst_ip",
            "cycle",
        ]
        _write_csv(output_file, events, fieldnames)
        outputs.append(str(output_file))
        return outputs

    counts: dict[str, int] = {}
    src_counts: dict[str, int] = {}
    dst_counts: dict[str, int] = {}
    qname_counts: dict[str, int] = {}
    for event in events:
        etype = event.get("type", "unknown")
        counts[etype] = counts.get(etype, 0) + 1
        src = event.get("src_ip")
        if src:
            src_counts[src] = src_counts.get(src, 0) + 1
        dst = event.get("dst_ip")
        if dst:
            dst_counts[dst] = dst_counts.get(dst, 0) + 1
        qname = event.get("qname")
        if qname:
            qname_counts[qname] = qname_counts.get(qname, 0) + 1

    if fmt == "html":
        html = []
        html.append("<html><head><meta charset='utf-8'><title>ARP Report</title>")
        html.append("<style>body{font-family:Arial,sans-serif}table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:4px 8px}</style>")
        html.append("</head><body>")
        html.append(_write_html_table("Event Counts", [{"type": k, "count": v} for k, v in counts.items()], ["type", "count"]))
        if src_counts:
            html.append(
                _write_html_table(
                    "Top Source IPs",
                    [{"src_ip": k, "count": v} for k, v in sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:20]],
                    ["src_ip", "count"],
                )
            )
        if dst_counts:
            html.append(
                _write_html_table(
                    "Top Destination IPs",
                    [{"dst_ip": k, "count": v} for k, v in sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:20]],
                    ["dst_ip", "count"],
                )
            )
        if qname_counts:
            html.append(
                _write_html_table(
                    "Top Query Names",
                    [{"qname": k, "count": v} for k, v in sorted(qname_counts.items(), key=lambda x: x[1], reverse=True)[:20]],
                    ["qname", "count"],
                )
            )
        html.append(
            _write_html_table(
                "Events",
                events,
                ["type", "ip", "mac", "old_mac", "new_mac", "count", "window", "ts", "src_ip", "dst_ip", "cycle"],
            )
        )
        html.append("</body></html>")
        output_file.write_text("".join(html), encoding="ascii")
        outputs.append(str(output_file))
    else:
        md = []
        md.append(_write_markdown_table("Event Counts", [{"type": k, "count": v} for k, v in counts.items()], ["type", "count"]))
        if src_counts:
            md.append(
                _write_markdown_table(
                    "Top Source IPs",
                    [{"src_ip": k, "count": v} for k, v in sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:20]],
                    ["src_ip", "count"],
                )
            )
        if dst_counts:
            md.append(
                _write_markdown_table(
                    "Top Destination IPs",
                    [{"dst_ip": k, "count": v} for k, v in sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:20]],
                    ["dst_ip", "count"],
                )
            )
        if qname_counts:
            md.append(
                _write_markdown_table(
                    "Top Query Names",
                    [{"qname": k, "count": v} for k, v in sorted(qname_counts.items(), key=lambda x: x[1], reverse=True)[:20]],
                    ["qname", "count"],
                )
            )
        md.append(
            _write_markdown_table(
                "Events",
                events,
                ["type", "ip", "mac", "old_mac", "new_mac", "count", "window", "ts", "src_ip", "dst_ip", "cycle"],
            )
        )
        output_file.write_text("".join(md), encoding="ascii")
        outputs.append(str(output_file))

    timeline_path = output_file.with_suffix("")
    timeline_path = Path(f"{timeline_path}_timeline.csv")
    _write_timeline_csv(timeline_path, events)
    outputs.append(str(timeline_path))
    return outputs
