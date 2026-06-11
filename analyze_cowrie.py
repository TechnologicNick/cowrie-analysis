#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Iterable

import pandas as pd
from tqdm import tqdm


FINGERPRINT_PATTERNS: list[tuple[str, list[re.Pattern[str]]]] = [
    (
        "fingerprinting/recon",
        [
            re.compile(r"\bhostname\b"),
            re.compile(r"\buname(?:\s|$)"),
            re.compile(r"/proc/cpuinfo"),
            re.compile(r"\blscpu\b"),
            re.compile(r"/etc/os-release"),
            re.compile(r"\bid\b"),
            re.compile(r"\bwhoami\b"),
            re.compile(r"\bps\b"),
            re.compile(r"\bip\s+a\b"),
            re.compile(r"\bifconfig\b"),
            re.compile(r"\bfree\b"),
            re.compile(r"\bmount\b"),
            re.compile(r"\bnproc\b"),
            re.compile(r"\bcat\s+/etc/issue\b"),
            re.compile(r"\bcat\s+/proc/version\b"),
        ],
    ),
    (
        "credential_persistence",
        [
            re.compile(r"\.ssh"),
            re.compile(r"authorized_keys"),
            re.compile(r"\bchpasswd\b"),
            re.compile(r"\buseradd\b"),
            re.compile(r"\badduser\b"),
            re.compile(r"\bpasswd\b"),
            re.compile(r"\busermod\b"),
        ],
    ),
    (
        "download_exec",
        [
            re.compile(r"\bwget\b"),
            re.compile(r"\bcurl\b"),
            re.compile(r"\btftp\b"),
            re.compile(r"\bftpget\b"),
            re.compile(r"\bchmod\b"),
            re.compile(r"/tmp/"),
            re.compile(r"\bbase64\b"),
        ],
    ),
    (
        "proxy_tunnel",
        [
            re.compile(r"\bssh\b.*\s-[LRD]"),
            re.compile(r"\bsocat\b"),
            re.compile(r"\bnc\b"),
            re.compile(r"\btelnet\b"),
        ],
    ),
    (
        "cleanup/evasion",
        [
            re.compile(r"\brm\s+-rf\b"),
            re.compile(r"\bhistory\s+-c\b"),
            re.compile(r"\bunset\s+HISTFILE\b"),
            re.compile(r"\bchattr\b"),
            re.compile(r"\blockr\b"),
            re.compile(r"\bpkill\b"),
            re.compile(r"\bkillall\b"),
        ],
    ),
]


EVENT_LABELS = {
    "cowrie.session.connect": "session.connect",
    "cowrie.client.version": "client.version",
    "cowrie.client.kex": "client.kex",
    "cowrie.login.success": "login.success",
    "cowrie.login.failed": "login.failed",
    "cowrie.session.params": "session.params",
    "cowrie.command.failed": "command.failed",
    "cowrie.direct-tcpip.request": "direct-tcpip.request",
    "cowrie.direct-tcpip.data": "direct-tcpip.data",
    "cowrie.direct-tcpip.ja4": "direct-tcpip.ja4",
    "cowrie.direct-tcpip.ja4h": "direct-tcpip.ja4h",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.file_upload": "file_upload",
    "cowrie.session.file_download.failed": "file_download.failed",
    "cowrie.log.closed": "log.closed",
    "cowrie.session.closed": "session.closed",
    "cowrie.client.fingerprint": "client.fingerprint",
    "cowrie.client.size": "client.size",
    "cowrie.client.var": "client.var",
}


@dataclass
class SessionSummary:
    sensor: str
    session: str
    src_ip: str | None
    dst_ip: str | None
    start_time: str | None
    end_time: str | None
    duration_s: float | None
    version_seen: bool
    client_version: str | None
    kex_seen: bool
    hassh: str | None
    auth_success: bool
    auth_failed: bool
    shell_opened: bool
    commands_run: int
    command_family: str
    first_command: str | None
    tunnel_activity: bool
    file_transfer: bool
    tty_closed: bool
    session_closed: bool
    close_stage: str
    actor_key: str
    fingerprinting_session: bool


def normalize_command(command: str) -> str:
    return " ".join(command.strip().split())


def display_label(label: str, limit: int = 44) -> str:
    return label if len(label) <= limit else f"{label[: limit - 1]}…"


def node_label_prefix(node_type: str) -> str:
    return {
        "root": "root",
        "event": "event",
        "command": "cmd",
        "terminal": "end",
    }.get(node_type, node_type)


DISPLAY_TO_EVENTID = {display: eventid for eventid, display in EVENT_LABELS.items()}


def event_display_name(eventid: str) -> str:
    return EVENT_LABELS.get(eventid, eventid.replace("cowrie.", ""))


def classify_command(command: str) -> str:
    command_lower = command.lower()
    for family, patterns in FINGERPRINT_PATTERNS:
        if any(pattern.search(command_lower) for pattern in patterns):
            return family
    return "other"


def splunk_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def sensor_count_column(sensor: str) -> str:
    return f"{sensor}_count"


def sensor_session_column(sensor: str) -> str:
    return f"{sensor}_sessions"


def sensor_first_command_column(sensor: str) -> str:
    return f"{sensor}_first_command"


def sensor_command_family_column(sensor: str) -> str:
    return f"{sensor}_command_family"


def build_sensor_counts(record: dict[str, Any], sensors: list[str], suffix: str = "_count") -> dict[str, int]:
    return {sensor: int(record.get(f"{sensor}{suffix}", 0) or 0) for sensor in sensors}


def iter_log_files(sensor_dir: Path) -> Iterable[Path]:
    log_dir = sensor_dir / "log"
    if not log_dir.exists():
        return []
    return sorted(path for path in log_dir.glob("cowrie.json*") if path.is_file())


def load_events(input_root: Path, sensors: list[str], from_date: str | None, to_date: str | None) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    from_ts = pd.Timestamp(from_date).tz_localize("UTC") if from_date else None
    to_ts = pd.Timestamp(to_date).tz_localize("UTC") + pd.Timedelta(days=1) if to_date else None
    log_files = [
        (sensor, log_file)
        for sensor in sensors
        for log_file in iter_log_files(input_root / sensor)
    ]
    total_bytes = sum(log_file.stat().st_size for _, log_file in log_files)
    progress = tqdm(total=total_bytes, unit="B", unit_scale=True, desc="Loading Cowrie logs")

    for sensor, log_file in log_files:
        progress.set_postfix_str(f"{sensor}/{log_file.name}")
        with log_file.open("rb") as handle:
            for raw_line in handle:
                progress.update(len(raw_line))
                line = raw_line.strip()
                if isinstance(line, bytes):
                    line = line.decode("utf-8", errors="ignore")
                    if not line:
                        continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                timestamp = pd.to_datetime(event.get("timestamp"), utc=True, errors="coerce")
                if pd.isna(timestamp):
                    continue
                if from_ts is not None and timestamp < from_ts:
                    continue
                if to_ts is not None and timestamp >= to_ts:
                    continue

                event["timestamp"] = timestamp
                event["sensor"] = sensor
                event["session_key"] = f"{sensor}:{event.get('session', '')}"
                rows.append(event)
    progress.close()

    frame = pd.DataFrame(rows)
    if frame.empty:
        return frame
    return frame.sort_values(["sensor", "session", "timestamp", "eventid"], kind="stable").reset_index(drop=True)


def derive_close_stage(eventids: set[str], session_closed: bool) -> str:
    if not session_closed:
        return "still_open"
    if "cowrie.session.file_download" in eventids or "cowrie.session.file_upload" in eventids:
        return "closed_after_file_transfer"
    if "cowrie.direct-tcpip.request" in eventids or "cowrie.direct-tcpip.data" in eventids:
        return "closed_after_tunnel"
    if "cowrie.command.input" in eventids:
        return "closed_after_command"
    if "cowrie.login.success" in eventids:
        return "closed_after_login"
    if "cowrie.login.failed" in eventids:
        return "closed_after_auth_failure"
    if "cowrie.client.kex" in eventids:
        return "closed_after_kex"
    if "cowrie.client.version" in eventids:
        return "closed_after_version"
    return "closed_before_version"


def summarize_commands(session_events: pd.DataFrame) -> tuple[int, str, str | None, bool]:
    commands = [normalize_command(cmd) for cmd in session_events.loc[session_events["eventid"] == "cowrie.command.input", "input"].dropna()]
    if not commands:
        return 0, "no_command", None, False
    families = [classify_command(command) for command in commands]
    family_counts = Counter(families)
    return (
        len(commands),
        family_counts.most_common(1)[0][0],
        commands[0],
        any(family == "fingerprinting/recon" for family in families),
    )


def _clean_optional(value: Any) -> Any:
    return None if pd.isna(value) else value


def build_session_artifacts(
    events: pd.DataFrame,
    sensors: list[str],
    max_node_flows: int = 12,
    max_flow_sessions: int = 3,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    session_records: list[SessionSummary] = []
    node_counter: dict[tuple[int, str, str], dict[str, Any]] = {}
    edge_counter: dict[tuple[tuple[int, str, str], tuple[int, str, str]], dict[str, Any]] = {}
    path_prefix_counter: dict[str, Counter[tuple[str, ...]]] = {sensor: Counter() for sensor in sensors}
    node_flow_details: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    session_path_rows: list[dict[str, Any]] = []
    count_columns = [sensor_count_column(sensor) for sensor in sensors]

    session_groups = events.groupby(["sensor", "session"], sort=False)
    total_sessions = int(events["session_key"].nunique())
    for (sensor, session), session_events in tqdm(
        session_groups,
        total=total_sessions,
        unit="session",
        desc="Building session artifacts",
    ):
        eventids = set(session_events["eventid"].tolist())
        first = session_events.iloc[0]
        last = session_events.iloc[-1]
        commands_run, command_family, first_command, fingerprinting_session = summarize_commands(session_events)
        hassh_values = session_events.loc[session_events["eventid"] == "cowrie.client.kex", "hassh"].dropna()
        version_values = session_events.loc[session_events["eventid"] == "cowrie.client.version", "version"].dropna()
        hassh = hassh_values.iloc[0] if not hassh_values.empty else None
        client_version = version_values.iloc[0] if not version_values.empty else None
        duration_values = session_events.loc[session_events["eventid"] == "cowrie.session.closed", "duration"].dropna()
        duration_s = None
        if not duration_values.empty:
            try:
                duration_s = float(duration_values.iloc[-1])
            except (TypeError, ValueError):
                duration_s = None

        actor_key = f"{_clean_optional(first.get('src_ip')) or 'unknown'}|{hassh or client_version or 'no-version'}"
        session_closed = "cowrie.session.closed" in eventids

        session_records.append(
            SessionSummary(
                sensor=sensor,
                session=str(session),
                src_ip=_clean_optional(first.get("src_ip")),
                dst_ip=_clean_optional(first.get("dst_ip")),
                start_time=first.get("timestamp").isoformat() if pd.notna(first.get("timestamp")) else None,
                end_time=last.get("timestamp").isoformat() if pd.notna(last.get("timestamp")) else None,
                duration_s=duration_s,
                version_seen="cowrie.client.version" in eventids,
                client_version=client_version,
                kex_seen="cowrie.client.kex" in eventids,
                hassh=hassh,
                auth_success="cowrie.login.success" in eventids,
                auth_failed="cowrie.login.failed" in eventids,
                shell_opened="cowrie.session.params" in eventids,
                commands_run=commands_run,
                command_family=command_family,
                first_command=first_command,
                tunnel_activity=any(eventid in eventids for eventid in ["cowrie.direct-tcpip.request", "cowrie.direct-tcpip.data", "cowrie.direct-tcpip.ja4", "cowrie.direct-tcpip.ja4h"]),
                file_transfer=any(eventid in eventids for eventid in ["cowrie.session.file_download", "cowrie.session.file_upload"]),
                tty_closed="cowrie.log.closed" in eventids,
                session_closed=session_closed,
                close_stage=derive_close_stage(eventids, session_closed),
                actor_key=actor_key,
                fingerprinting_session=fingerprinting_session,
            )
        )

        path_nodes: list[dict[str, Any]] = [
            {
                "step_index": 0,
                "label": sensor,
                "node_type": "root",
                "command_family": "",
                "display_label": f"root: {sensor}",
                "full_display_label": f"root: {sensor}",
                "source_eventid": "",
            }
        ]
        prefix_labels = [sensor]

        for step_index, event in enumerate(session_events.itertuples(index=False), start=1):
            if event.eventid == "cowrie.command.input":
                label = normalize_command(getattr(event, "input", "") or "")
                node_type = "command"
                command_family_value = classify_command(label)
                source_eventid = "cowrie.command.input"
            else:
                label = event_display_name(event.eventid)
                node_type = "terminal" if event.eventid == "cowrie.session.closed" else "event"
                command_family_value = ""
                source_eventid = event.eventid

            prefix = node_label_prefix(node_type)
            path_nodes.append(
                {
                    "step_index": step_index,
                    "label": label,
                    "node_type": node_type,
                    "command_family": command_family_value,
                    "display_label": f"{prefix}: {display_label(label)}",
                    "full_display_label": f"{prefix}: {label}",
                    "source_eventid": source_eventid,
                }
            )
            prefix_labels.append(label)

        if path_nodes[-1]["label"] != "session.closed":
            path_nodes.append(
                {
                    "step_index": len(path_nodes),
                    "label": "still_open",
                    "node_type": "terminal",
                    "command_family": "",
                    "display_label": "end: still_open",
                    "full_display_label": "end: still_open",
                    "source_eventid": "",
                }
            )
            prefix_labels.append("still_open")

        full_path_labels = [node["full_display_label"] for node in path_nodes]
        full_path = " -> ".join(full_path_labels)
        flow_steps = [
            {
                "label": node["label"],
                "display_label": node["full_display_label"],
                "node_type": node["node_type"],
                "command_family": node["command_family"],
                "color_key": (
                    node["command_family"]
                    if node["node_type"] == "command"
                    else ("terminal" if node["node_type"] == "terminal" else node["node_type"])
                ),
            }
            for node in path_nodes
        ]

        path_prefix_counter[sensor][tuple(prefix_labels[:8])] += 1
        session_path_rows.append(
            {
                "sensor": sensor,
                "session": session,
                "path_length": len(path_nodes) - 1,
                "full_path": full_path,
                "path_preview": " -> ".join(prefix_labels[:12]),
            }
        )

        for node in path_nodes:
            node_key = (node["step_index"], node["label"], node["node_type"])
            node_id = f"{node['step_index']}|{node['node_type']}|{node['label']}"
            if node_key not in node_counter:
                node_counter[node_key] = {
                    "node_id": node_id,
                    "step_index": node["step_index"],
                    "label": node["label"],
                    "display_label": node["display_label"],
                    "full_display_label": node["full_display_label"],
                    "node_type": node["node_type"],
                    "command_family": node["command_family"],
                    "source_eventid": node["source_eventid"],
                    **{sensor_count_column(sensor_name): 0 for sensor_name in sensors},
                }
            node_counter[node_key][sensor_count_column(sensor)] += 1
            flow_detail = node_flow_details[node_id].get(full_path)
            if flow_detail is None:
                flow_detail = {
                    "path": full_path,
                    "sensor": sensor,
                    "steps": flow_steps,
                    "sensor_counts": {sensor_name: 0 for sensor_name in sensors},
                    "total_count": 0,
                    "sample_sessions": [],
                }
                node_flow_details[node_id][full_path] = flow_detail
            flow_detail["sensor_counts"][sensor] += 1
            flow_detail["total_count"] += 1
            if len(flow_detail["sample_sessions"]) < max_flow_sessions:
                flow_detail["sample_sessions"].append({"sensor": sensor, "session": session})

        for source_node, target_node in zip(path_nodes, path_nodes[1:]):
            edge_key = (
                (source_node["step_index"], source_node["label"], source_node["node_type"]),
                (target_node["step_index"], target_node["label"], target_node["node_type"]),
            )
            if edge_key not in edge_counter:
                edge_counter[edge_key] = {
                    "source_id": f"{source_node['step_index']}|{source_node['node_type']}|{source_node['label']}",
                    "target_id": f"{target_node['step_index']}|{target_node['node_type']}|{target_node['label']}",
                    "source_step_index": source_node["step_index"],
                    "target_step_index": target_node["step_index"],
                    "source_label": source_node["label"],
                    "target_label": target_node["label"],
                    **{sensor_count_column(sensor_name): 0 for sensor_name in sensors},
                }
            edge_counter[edge_key][sensor_count_column(sensor)] += 1

    session_df = pd.DataFrame(asdict(record) for record in session_records)
    nodes_df = pd.DataFrame(node_counter.values())
    nodes_df["total_count"] = nodes_df[count_columns].sum(axis=1)
    nodes_df["sensor_counts"] = nodes_df.apply(
        lambda row: {sensor: int(row[sensor_count_column(sensor)]) for sensor in sensors},
        axis=1,
    )
    nodes_df["color_key"] = nodes_df.apply(
        lambda row: row["command_family"] if row["node_type"] == "command" else ("terminal" if row["node_type"] == "terminal" else row["node_type"]),
        axis=1,
    )
    nodes_df["top_flows"] = [
        sorted(
            node_flow_details.get(node_id, {}).values(),
            key=lambda item: (
                -item["total_count"],
                *[-int(item["sensor_counts"].get(sensor, 0)) for sensor in sensors],
                item["path"],
            ),
        )[:max_node_flows]
        for node_id in nodes_df["node_id"]
    ]

    edges_df = pd.DataFrame(edge_counter.values())
    edges_df["total_count"] = edges_df[count_columns].sum(axis=1)
    edges_df["sensor_counts"] = edges_df.apply(
        lambda row: {sensor: int(row[sensor_count_column(sensor)]) for sensor in sensors},
        axis=1,
    )
    edges_df["sensor_mix"] = edges_df["sensor_counts"].map(
        lambda counts: (
            active[0]
            if len(active := [sensor for sensor, count in counts.items() if count > 0]) == 1
            else ("multiple" if active else "none")
        )
    )
    edges_df = edges_df.sort_values(["source_step_index", "total_count"], ascending=[True, False]).reset_index(drop=True)
    nodes_df = compute_model_order(nodes_df, edges_df)

    top_paths_df = pd.DataFrame(
        [
            {"sensor": sensor, "path_prefix": " -> ".join(prefix), "count": count}
            for sensor, counter in path_prefix_counter.items()
            for prefix, count in counter.most_common()
        ]
    )
    session_paths_df = pd.DataFrame(session_path_rows)
    return session_df, nodes_df, edges_df, session_paths_df, top_paths_df


def build_session_table(events: pd.DataFrame) -> pd.DataFrame:
    records: list[SessionSummary] = []
    if events.empty:
        return pd.DataFrame()

    for (sensor, session), session_events in events.groupby(["sensor", "session"], sort=False):
        eventids = set(session_events["eventid"].tolist())
        first = session_events.iloc[0]
        last = session_events.iloc[-1]
        commands_run, command_family, first_command, fingerprinting_session = summarize_commands(session_events)
        hassh_values = session_events.loc[session_events["eventid"] == "cowrie.client.kex", "hassh"].dropna()
        version_values = session_events.loc[session_events["eventid"] == "cowrie.client.version", "version"].dropna()
        hassh = hassh_values.iloc[0] if not hassh_values.empty else None
        client_version = version_values.iloc[0] if not version_values.empty else None
        duration_values = session_events.loc[session_events["eventid"] == "cowrie.session.closed", "duration"].dropna()
        duration_s = None
        if not duration_values.empty:
            try:
                duration_s = float(duration_values.iloc[-1])
            except (TypeError, ValueError):
                duration_s = None

        actor_key = f"{first.get('src_ip', 'unknown')}|{hassh or client_version or 'no-version'}"
        session_closed = "cowrie.session.closed" in eventids

        records.append(
            SessionSummary(
                sensor=sensor,
                session=str(session),
                src_ip=first.get("src_ip"),
                dst_ip=first.get("dst_ip"),
                start_time=first.get("timestamp").isoformat() if pd.notna(first.get("timestamp")) else None,
                end_time=last.get("timestamp").isoformat() if pd.notna(last.get("timestamp")) else None,
                duration_s=duration_s,
                version_seen="cowrie.client.version" in eventids,
                client_version=client_version,
                kex_seen="cowrie.client.kex" in eventids,
                hassh=hassh,
                auth_success="cowrie.login.success" in eventids,
                auth_failed="cowrie.login.failed" in eventids,
                shell_opened="cowrie.session.params" in eventids,
                commands_run=commands_run,
                command_family=command_family,
                first_command=first_command,
                tunnel_activity=any(eventid in eventids for eventid in ["cowrie.direct-tcpip.request", "cowrie.direct-tcpip.data", "cowrie.direct-tcpip.ja4", "cowrie.direct-tcpip.ja4h"]),
                file_transfer=any(eventid in eventids for eventid in ["cowrie.session.file_download", "cowrie.session.file_upload"]),
                tty_closed="cowrie.log.closed" in eventids,
                session_closed=session_closed,
                close_stage=derive_close_stage(eventids, session_closed),
                actor_key=actor_key,
                fingerprinting_session=fingerprinting_session,
            )
        )

    return pd.DataFrame(asdict(record) for record in records)


def build_stage_counts(session_df: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for sensor, group in session_df.groupby("sensor"):
        rows.extend(
            [
                {"sensor": sensor, "stage": "session_start", "count": len(group), "pct_sessions": 1.0},
                {"sensor": sensor, "stage": "client_version", "count": int(group["version_seen"].sum()), "pct_sessions": group["version_seen"].mean()},
                {"sensor": sensor, "stage": "kex_completed", "count": int(group["kex_seen"].sum()), "pct_sessions": group["kex_seen"].mean()},
                {"sensor": sensor, "stage": "auth_success", "count": int(group["auth_success"].sum()), "pct_sessions": group["auth_success"].mean()},
                {"sensor": sensor, "stage": "shell_opened", "count": int(group["shell_opened"].sum()), "pct_sessions": group["shell_opened"].mean()},
                {"sensor": sensor, "stage": "commands_run", "count": int((group["commands_run"] > 0).sum()), "pct_sessions": (group["commands_run"] > 0).mean()},
                {"sensor": sensor, "stage": "tunnel_activity", "count": int(group["tunnel_activity"].sum()), "pct_sessions": group["tunnel_activity"].mean()},
                {"sensor": sensor, "stage": "file_transfer", "count": int(group["file_transfer"].sum()), "pct_sessions": group["file_transfer"].mean()},
                {"sensor": sensor, "stage": "tty_closed", "count": int(group["tty_closed"].sum()), "pct_sessions": group["tty_closed"].mean()},
                {"sensor": sensor, "stage": "session_closed", "count": int(group["session_closed"].sum()), "pct_sessions": group["session_closed"].mean()},
                {"sensor": sensor, "stage": "fingerprinting_recon", "count": int(group["fingerprinting_session"].sum()), "pct_sessions": group["fingerprinting_session"].mean()},
            ]
        )
    return pd.DataFrame(rows)


def build_fingerprinting_candidates(session_df: pd.DataFrame, sensors: list[str]) -> pd.DataFrame:
    seen_both = session_df.groupby("actor_key")["sensor"].nunique()
    compare = session_df[session_df["actor_key"].isin(seen_both[seen_both > 1].index)].copy()
    if compare.empty:
        return compare

    rows = []
    for actor_key, group in compare.groupby("actor_key"):
        row = {
            "actor_key": actor_key,
            "src_ip": group["src_ip"].dropna().iloc[0] if not group["src_ip"].dropna().empty else None,
            "hassh": group["hassh"].dropna().iloc[0] if not group["hassh"].dropna().empty else None,
            "client_version": group["client_version"].dropna().iloc[0] if not group["client_version"].dropna().empty else None,
            "sensors_seen": ",".join(sorted(group["sensor"].unique())),
            "sessions_total": int(len(group)),
        }
        first_commands: set[str] = set()
        command_families: set[str] = set()
        for sensor in sensors:
            first_command = next((value for value in group.loc[group["sensor"] == sensor, "first_command"].tolist() if isinstance(value, str)), None)
            command_family = next((value for value in group.loc[group["sensor"] == sensor, "command_family"].tolist() if isinstance(value, str)), None)
            row[sensor_first_command_column(sensor)] = first_command
            row[sensor_command_family_column(sensor)] = command_family
            row[sensor_session_column(sensor)] = int((group["sensor"] == sensor).sum())
            if first_command:
                first_commands.add(first_command)
            if command_family:
                command_families.add(command_family)
        row["unique_first_commands"] = len(first_commands)
        row["unique_command_families"] = len(command_families)
        rows.append(row)
    result = pd.DataFrame(rows)
    result["first_command_differs"] = result["unique_first_commands"] > 1
    result["command_family_differs"] = result["unique_command_families"] > 1
    return result.sort_values(
        ["command_family_differs", "first_command_differs", "sessions_total"],
        ascending=[False, False, False],
    )


def build_top_tables(events: pd.DataFrame, session_df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    top_hassh = (
        events.loc[events["eventid"] == "cowrie.client.kex", ["sensor", "hassh"]]
        .dropna()
        .value_counts()
        .rename("count")
        .reset_index()
        .sort_values(["sensor", "count"], ascending=[True, False])
    )
    top_versions = (
        events.loc[events["eventid"] == "cowrie.client.version", ["sensor", "version"]]
        .dropna()
        .value_counts()
        .rename("count")
        .reset_index()
        .sort_values(["sensor", "count"], ascending=[True, False])
    )
    top_commands = (
        events.loc[events["eventid"] == "cowrie.command.input", ["sensor", "input"]]
        .dropna()
        .assign(input=lambda df: df["input"].map(normalize_command))
        .value_counts()
        .rename("count")
        .reset_index()
        .sort_values(["sensor", "count"], ascending=[True, False])
    )
    top_command_families = (
        session_df.loc[session_df["commands_run"] > 0, ["sensor", "command_family"]]
        .value_counts()
        .rename("count")
        .reset_index()
        .sort_values(["sensor", "count"], ascending=[True, False])
    )
    return {
        "top_hassh": top_hassh,
        "top_versions": top_versions,
        "top_commands": top_commands,
        "top_command_families": top_command_families,
    }


def compute_model_order(nodes_df: pd.DataFrame, edges_df: pd.DataFrame) -> pd.DataFrame:
    work = nodes_df.copy()
    incoming_by_target: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for edge in edges_df.itertuples(index=False):
        incoming_by_target[edge.target_id].append((edge.source_id, int(edge.total_count)))

    order_lookup: dict[str, int] = {}
    barycenter_lookup: dict[str, float] = {}

    for step_index in sorted(work["step_index"].unique()):
        group = work.loc[work["step_index"] == step_index].copy()
        if step_index == 0:
            group = group.sort_values(["label"])
            for idx, row in enumerate(group.itertuples(index=False)):
                order_lookup[row.node_id] = idx
                barycenter_lookup[row.node_id] = float(idx)
            continue

        ranked_rows: list[tuple[str, float, int, str]] = []
        for row in group.itertuples(index=False):
            incoming = incoming_by_target.get(row.node_id, [])
            if incoming:
                weighted_sum = sum(order_lookup[source_id] * weight for source_id, weight in incoming if source_id in order_lookup)
                total_weight = sum(weight for source_id, weight in incoming if source_id in order_lookup)
                barycenter = weighted_sum / total_weight if total_weight else 0.0
            else:
                barycenter = 0.0
            ranked_rows.append((row.node_id, barycenter, -int(row.total_count), row.label))

        ranked_rows.sort(key=lambda item: (item[1], item[2], item[3]))
        for idx, (node_id, barycenter, _, _) in enumerate(ranked_rows):
            order_lookup[node_id] = idx
            barycenter_lookup[node_id] = barycenter

    work["model_order"] = work["node_id"].map(order_lookup).fillna(0).astype(int)
    work["incoming_barycenter"] = work["node_id"].map(barycenter_lookup).fillna(0.0)
    return work.sort_values(["step_index", "model_order", "label"]).reset_index(drop=True)


def build_session_paths(
    events: pd.DataFrame,
    sensors: list[str],
    max_node_flows: int = 12,
    max_flow_sessions: int = 3,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    node_counter: dict[tuple[int, str, str], dict[str, Any]] = {}
    edge_counter: dict[tuple[tuple[int, str, str], tuple[int, str, str]], dict[str, Any]] = {}
    path_prefix_counter: dict[str, Counter[tuple[str, ...]]] = {sensor: Counter() for sensor in sensors}
    node_flow_details: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    session_path_rows: list[dict[str, Any]] = []

    for (sensor, session), session_events in events.groupby(["sensor", "session"], sort=False):
        path_nodes: list[dict[str, Any]] = [
            {
                "step_index": 0,
                "label": sensor,
                "node_type": "root",
                "command_family": "",
                "display_label": f"root: {sensor}",
                "full_display_label": f"root: {sensor}",
                "source_eventid": "",
            }
        ]
        prefix_labels = [sensor]

        for step_index, event in enumerate(session_events.itertuples(index=False), start=1):
            if event.eventid == "cowrie.command.input":
                label = normalize_command(getattr(event, "input", "") or "")
                node_type = "command"
                command_family = classify_command(label)
                source_eventid = "cowrie.command.input"
            else:
                label = event_display_name(event.eventid)
                node_type = "terminal" if event.eventid == "cowrie.session.closed" else "event"
                command_family = ""
                source_eventid = event.eventid

            prefix = node_label_prefix(node_type)
            path_nodes.append(
                {
                    "step_index": step_index,
                    "label": label,
                    "node_type": node_type,
                    "command_family": command_family,
                    "display_label": f"{prefix}: {display_label(label)}",
                    "full_display_label": f"{prefix}: {label}",
                    "source_eventid": source_eventid,
                }
            )
            prefix_labels.append(label)

        if path_nodes[-1]["label"] != "session.closed":
            path_nodes.append(
                {
                    "step_index": len(path_nodes),
                    "label": "still_open",
                    "node_type": "terminal",
                    "command_family": "",
                    "display_label": "end: still_open",
                    "full_display_label": "end: still_open",
                    "source_eventid": "",
                }
            )
            prefix_labels.append("still_open")

        full_path_labels = [node["full_display_label"] for node in path_nodes]
        full_path = " -> ".join(full_path_labels)
        flow_steps = [
            {
                "label": node["label"],
                "display_label": node["full_display_label"],
                "node_type": node["node_type"],
                "command_family": node["command_family"],
                "color_key": (
                    node["command_family"]
                    if node["node_type"] == "command"
                    else ("terminal" if node["node_type"] == "terminal" else node["node_type"])
                ),
            }
            for node in path_nodes
        ]

        path_prefix_counter[sensor][tuple(prefix_labels[:8])] += 1
        session_path_rows.append(
            {
                "sensor": sensor,
                "session": session,
                "path_length": len(path_nodes) - 1,
                "full_path": full_path,
                "path_preview": " -> ".join(prefix_labels[:12]),
            }
        )

        for node in path_nodes:
            node_key = (node["step_index"], node["label"], node["node_type"])
            node_id = f"{node['step_index']}|{node['node_type']}|{node['label']}"
            if node_key not in node_counter:
                node_counter[node_key] = {
                    "node_id": node_id,
                    "step_index": node["step_index"],
                    "label": node["label"],
                    "display_label": node["display_label"],
                    "full_display_label": node["full_display_label"],
                    "node_type": node["node_type"],
                    "command_family": node["command_family"],
                    "source_eventid": node["source_eventid"],
                    **{sensor_count_column(sensor): 0 for sensor in sensors},
                }
            node_counter[node_key][sensor_count_column(sensor)] += 1
            flow_detail = node_flow_details[node_id].get(full_path)
            if flow_detail is None:
                flow_detail = {
                    "path": full_path,
                    "sensor": sensor,
                    "steps": flow_steps,
                    "sensor_counts": {sensor_name: 0 for sensor_name in sensors},
                    "total_count": 0,
                    "sample_sessions": [],
                }
                node_flow_details[node_id][full_path] = flow_detail
            flow_detail["sensor_counts"][sensor] += 1
            flow_detail["total_count"] += 1
            if len(flow_detail["sample_sessions"]) < max_flow_sessions:
                flow_detail["sample_sessions"].append({"sensor": sensor, "session": session})

        for source_node, target_node in zip(path_nodes, path_nodes[1:]):
            edge_key = (
                (source_node["step_index"], source_node["label"], source_node["node_type"]),
                (target_node["step_index"], target_node["label"], target_node["node_type"]),
            )
            if edge_key not in edge_counter:
                edge_counter[edge_key] = {
                    "source_id": f"{source_node['step_index']}|{source_node['node_type']}|{source_node['label']}",
                    "target_id": f"{target_node['step_index']}|{target_node['node_type']}|{target_node['label']}",
                    "source_step_index": source_node["step_index"],
                    "target_step_index": target_node["step_index"],
                    "source_label": source_node["label"],
                    "target_label": target_node["label"],
                    **{sensor_count_column(sensor): 0 for sensor in sensors},
                }
            edge_counter[edge_key][sensor_count_column(sensor)] += 1

    nodes_df = pd.DataFrame(node_counter.values())
    count_columns = [sensor_count_column(sensor) for sensor in sensors]
    nodes_df["total_count"] = nodes_df[count_columns].sum(axis=1)
    nodes_df["sensor_counts"] = nodes_df.apply(
        lambda row: {sensor: int(row[sensor_count_column(sensor)]) for sensor in sensors},
        axis=1,
    )
    nodes_df["color_key"] = nodes_df.apply(
        lambda row: row["command_family"] if row["node_type"] == "command" else ("terminal" if row["node_type"] == "terminal" else row["node_type"]),
        axis=1,
    )
    top_flow_records: list[list[dict[str, Any]]] = []
    for node_id in nodes_df["node_id"]:
        ranked = sorted(
            node_flow_details.get(node_id, {}).values(),
            key=lambda item: (
                -item["total_count"],
                *[-int(item["sensor_counts"].get(sensor, 0)) for sensor in sensors],
                item["path"],
            ),
        )
        top_flow_records.append(ranked[:max_node_flows])
    nodes_df["top_flows"] = top_flow_records

    edges_df = pd.DataFrame(edge_counter.values())
    edges_df["total_count"] = edges_df[count_columns].sum(axis=1)
    edges_df["sensor_counts"] = edges_df.apply(
        lambda row: {sensor: int(row[sensor_count_column(sensor)]) for sensor in sensors},
        axis=1,
    )
    edges_df["sensor_mix"] = edges_df["sensor_counts"].map(
        lambda counts: (
            active[0]
            if len(active := [sensor for sensor, count in counts.items() if count > 0]) == 1
            else ("multiple" if active else "none")
        )
    )
    edges_df = edges_df.sort_values(["source_step_index", "total_count"], ascending=[True, False]).reset_index(drop=True)
    nodes_df = compute_model_order(nodes_df, edges_df)

    path_rows = []
    for sensor, counter in path_prefix_counter.items():
        for prefix, count in counter.most_common():
            path_rows.append({"sensor": sensor, "path_prefix": " -> ".join(prefix), "count": count})
    top_paths_df = pd.DataFrame(path_rows)

    return nodes_df, edges_df, pd.DataFrame(session_path_rows), top_paths_df


def build_graph_json(
    nodes_df: pd.DataFrame,
    edges_df: pd.DataFrame,
    session_df: pd.DataFrame,
    sensors: list[str],
    from_date: str | None,
    to_date: str | None,
) -> dict[str, Any]:
    return {
        "meta": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "from_date": from_date,
            "to_date": to_date,
            "sensors": sensors,
            "session_count": int(len(session_df)),
            "max_step_index": int(nodes_df["step_index"].max()) if not nodes_df.empty else 0,
            "node_count": int(len(nodes_df)),
            "edge_count": int(len(edges_df)),
        },
        "nodes": nodes_df.to_dict(orient="records"),
        "edges": edges_df.to_dict(orient="records"),
    }


def format_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def build_summary_markdown(
    session_df: pd.DataFrame,
    stage_counts: pd.DataFrame,
    fingerprinting_candidates: pd.DataFrame,
    top_tables: dict[str, pd.DataFrame],
    top_paths_df: pd.DataFrame,
    sensors: list[str],
    max_summary_paths: int,
    max_summary_rows: int,
) -> str:
    lines = ["# Cowrie Analysis Summary", "", "## Session Volume"]
    for sensor, group in session_df.groupby("sensor"):
        lines.append(f"- `{sensor}`: {len(group)} sessions")

    lines.extend(["", "## Stage Conversions"])
    for sensor, group in stage_counts.groupby("sensor"):
        lines.append(f"- `{sensor}`:")
        for _, row in group.iterrows():
            lines.append(f"  - {row['stage']}: {int(row['count'])} ({format_pct(row['pct_sessions'])})")

    lines.extend(["", "## Dominant State-Machine Prefixes"])
    for sensor in sorted(top_paths_df["sensor"].unique()):
        lines.append(f"- `{sensor}`:")
        for _, row in top_paths_df.loc[top_paths_df["sensor"] == sensor].head(max_summary_paths).iterrows():
            lines.append(f"  - {row['count']}: {row['path_prefix']}")

    lines.extend(["", "## Top Fingerprinting Indicators"])
    recon = session_df.groupby("sensor")["fingerprinting_session"].mean()
    for sensor, pct in recon.items():
        lines.append(f"- `{sensor}` fingerprinting/recon sessions: {format_pct(pct)}")

    for table_name, title in [
        ("top_hassh", "Top HASSH"),
        ("top_versions", "Top Client Versions"),
        ("top_command_families", "Top Command Families"),
        ("top_commands", "Top Raw Commands"),
    ]:
        lines.extend(["", f"### {title}"])
        table = top_tables[table_name]
        for sensor in sorted(table["sensor"].unique()):
            lines.append(f"- `{sensor}`:")
            subset = table.loc[table["sensor"] == sensor].head(max_summary_rows)
            label_column = [col for col in subset.columns if col not in {"sensor", "count"}][0]
            for _, row in subset.iterrows():
                lines.append(f"  - {row[label_column]}: {int(row['count'])}")

    lines.extend(["", "## Cross-Sensor Actor Comparison"])
    if fingerprinting_candidates.empty:
        lines.append("- No actors were observed on both sensors within the selected window.")
    else:
        for _, row in fingerprinting_candidates.head(15).iterrows():
            sensor_details = " ".join(
                f"{sensor}=`{row.get(sensor_command_family_column(sensor))}`"
                for sensor in sensors
                if pd.notna(row.get(sensor_command_family_column(sensor)))
            )
            lines.append(
                f"- `{row['src_ip']}` `{row['hassh'] or row['client_version']}`: "
                f"{sensor_details} "
                f"first_command_differs={row['first_command_differs']}"
            )

    lines.extend(["", "## Likely Differentiators"])
    recon_rates = []
    for sensor in sensors:
        sensor_sessions = session_df.loc[session_df["sensor"] == sensor]
        recon_rate = sensor_sessions["fingerprinting_session"].mean() if not sensor_sessions.empty else 0.0
        recon_rates.append((sensor, recon_rate))
    for sensor, recon_rate in sorted(recon_rates, key=lambda item: item[1], reverse=True):
        lines.append(f"- `{sensor}` recon activity rate: {format_pct(recon_rate)}.")
    lines.append("- The ELK renderer consumes `cowrie_state_machine_graph.json` directly, so layout iteration no longer requires raw-log reanalysis.")
    return "\n".join(lines) + "\n"


def write_dataframe(df: pd.DataFrame, path: Path) -> None:
    if path.suffix == ".parquet":
        try:
            df.to_parquet(path, index=False)
            return
        except Exception:
            df.to_csv(path.with_suffix(".csv"), index=False)
            return
    df.to_csv(path, index=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze Cowrie honeypot logs and render state-machine SVGs.")
    subparsers = parser.add_subparsers(dest="command")

    def add_common_args(target: argparse.ArgumentParser) -> None:
        target.add_argument("--artifact-dir", default="honeypot/analysis/artifacts")

    analyze = subparsers.add_parser("analyze", help="Parse raw Cowrie logs and build analysis artifacts.")
    analyze.add_argument("--input-root", default="honeypot/outputs")
    analyze.add_argument("--sensors", default="baseline,hostname,banner")
    analyze.add_argument("--from", dest="from_date", default=None)
    analyze.add_argument("--to", dest="to_date", default=None)
    analyze.add_argument("--max-summary-paths", type=int, default=8)
    analyze.add_argument("--max-summary-rows", type=int, default=6)
    add_common_args(analyze)

    render = subparsers.add_parser("render", help="Render the SVG from a previously generated graph JSON.")
    add_common_args(render)
    render.add_argument("--graph-json", default=None)
    render.add_argument("--output-svg", default=None)
    render.add_argument("--node-script", default="honeypot/analysis/render_state_machine.mjs")

    return parser.parse_args()


def run_analyze(args: argparse.Namespace) -> None:
    input_root = Path(args.input_root)
    artifact_dir = Path(args.artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    sensors = [sensor.strip() for sensor in args.sensors.split(",") if sensor.strip()]

    events = load_events(input_root, sensors, args.from_date, args.to_date)
    if events.empty:
        raise SystemExit("No events found for the selected sensors/date range.")

    session_df, state_nodes, state_edges, session_paths, top_paths_df = build_session_artifacts(events, sensors)
    stage_counts = build_stage_counts(session_df)
    fingerprinting_candidates = build_fingerprinting_candidates(session_df, sensors)
    top_tables = build_top_tables(events, session_df)
    graph_json = build_graph_json(state_nodes, state_edges, session_df, sensors, args.from_date, args.to_date)

    write_dataframe(session_df, artifact_dir / "cowrie_sessions.parquet")
    stage_counts.to_csv(artifact_dir / "cowrie_stage_counts.csv", index=False)
    fingerprinting_candidates.to_csv(artifact_dir / "cowrie_fingerprinting_candidates.csv", index=False)
    state_nodes.to_csv(artifact_dir / "cowrie_state_machine_nodes.csv", index=False)
    state_edges.to_csv(artifact_dir / "cowrie_state_machine_edges.csv", index=False)
    session_paths.to_csv(artifact_dir / "cowrie_session_paths.csv", index=False)
    top_paths_df.to_csv(artifact_dir / "cowrie_top_path_prefixes.csv", index=False)
    for name, table in top_tables.items():
        table.to_csv(artifact_dir / f"{name}.csv", index=False)

    (artifact_dir / "cowrie_state_machine_graph.json").write_text(json.dumps(graph_json, indent=2), encoding="utf-8")

    summary = build_summary_markdown(
        session_df=session_df,
        stage_counts=stage_counts,
        fingerprinting_candidates=fingerprinting_candidates,
        top_tables=top_tables,
        top_paths_df=top_paths_df,
        sensors=sensors,
        max_summary_paths=args.max_summary_paths,
        max_summary_rows=args.max_summary_rows,
    )
    (artifact_dir / "cowrie_summary.md").write_text(summary, encoding="utf-8")

    print(f"Analyzed {len(events)} events across {len(session_df)} sessions.")
    print(f"State nodes: {len(state_nodes)}")
    print(f"State edges: {len(state_edges)}")
    print(f"Artifacts written to {artifact_dir}")


def run_render(args: argparse.Namespace) -> None:
    artifact_dir = Path(args.artifact_dir)
    graph_json = Path(args.graph_json) if args.graph_json else artifact_dir / "cowrie_state_machine_graph.json"
    output_svg = Path(args.output_svg) if args.output_svg else artifact_dir / "cowrie_state_machine.svg"
    node_script = Path(args.node_script)

    if not graph_json.exists():
        raise SystemExit(f"Graph JSON not found: {graph_json}")
    if not node_script.exists():
        raise SystemExit(f"Node renderer not found: {node_script}")

    subprocess.run(
        ["node", str(node_script), str(graph_json), str(output_svg)],
        check=True,
    )
    print(f"Rendered SVG to {output_svg}")


def main() -> None:
    args = parse_args()
    if args.command == "render":
        run_render(args)
        return
    if args.command in {None, "analyze"}:
        run_analyze(args)
        return
    raise SystemExit(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    main()
