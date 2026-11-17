# -*- coding: utf-8 -*-
"""
导出模块：把分析结果导出为 HTML / JSON / TXT / CSV(Excel) / XLSX / Zip。
所有导出均为「只读」数据的复制，不修改任何源数据。
"""
import os
import io
import json
import zipfile
import csv
import datetime

from db import WeChatDB, word_emoji_freq


def _ts_to_str(ts):
    if not ts:
        return ""
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def collect(db, talker=None, year=None):
    """收集要导出的数据。"""
    data = {"generated_at": _ts_to_str(int(__import__("time").time())),
            "talker": talker, "year": year, "conversations": [], "messages": [],
            "favorites": [], "moments": [], "annual": None}
    # 会话列表
    data["conversations"] = db.conversations(limit=500)
    # 消息
    if talker:
        msgs = db.messages(talker, page=0, page_size=10**9)
        for m in msgs:
            data["messages"].append({
                "time": _ts_to_str(m["time"]),
                "isSend": m["isSend"],
                "content": m["content"],
            })
    else:
        # 全部会话的最新若干条（避免过大）：每个会话取前 200 条
        for c in data["conversations"][:50]:
            msgs = db.messages(c["talker"], page=0, page_size=200)
            for m in msgs:
                data["messages"].append({
                    "talker": c["talker"], "name": c["name"],
                    "time": _ts_to_str(m["time"]), "isSend": m["isSend"],
                    "content": m["content"],
                })
    # 收藏 / 朋友圈
    data["favorites"] = db.favorites(limit=500)
    data["moments"] = db.moments(limit=500)
    return data


def export_json(data):
    return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")


def export_txt(data):
    lines = []
    lines.append("微信聊天数据导出（只读分析）")
    lines.append("生成时间: " + data["generated_at"])
    lines.append("=" * 40)
    if data["talker"]:
        lines.append("会话: " + data["talker"])
        for m in data["messages"]:
            who = "我" if m["isSend"] else "对方"
            lines.append(f"[{m['time']}] {who}: {m['content']}")
    else:
        for m in data["messages"]:
            who = "我" if m["isSend"] else "对方"
            lines.append(f"[{m['time']}] {m['name']}/{who}: {m['content']}")
    if data["favorites"]:
        lines.append("\n--- 收藏 ---")
        for f in data["favorites"]:
            lines.append(f"[{f['time']}] {f['title']} ({f['type']})")
    if data["moments"]:
        lines.append("\n--- 朋友圈(本地) ---")
        for s in data["moments"]:
            lines.append(f"[{s['time']}] {s['content']}")
    return ("\n".join(lines)).encode("utf-8")


def export_csv(data):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["会话", "名称", "时间", "发送方(1=我)", "内容"])
    for m in data["messages"]:
        w.writerow([m.get("talker", ""), m.get("name", ""),
                    m["time"], m["isSend"], m["content"]])
    # Excel 打开 UTF-8 CSV 需 BOM
    return ("\ufeff" + buf.getvalue()).encode("utf-8")


def export_html(data):
    html = ["<html><head><meta charset='utf-8'><title>微信数据导出</title>",
            "<style>body{font-family:sans-serif;padding:20px} "
            ".msg{border-bottom:1px solid #eee;padding:6px} "
            ".me{color:#07c160}.them{color:#333} "
            "table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px}</style></head><body>"]
    html.append(f"<h1>微信聊天数据导出</h1><p>生成时间: {data['generated_at']}</p>")
    if data["messages"]:
        html.append("<h2>消息</h2>")
        for m in data["messages"]:
            who = "me" if m["isSend"] else "them"
            name = m.get("name", "")
            html.append(f"<div class='msg {who}'>[{m['time']}] {name}: {_esc(m['content'])}</div>")
    if data["favorites"]:
        html.append("<h2>收藏</h2><ul>")
        for f in data["favorites"]:
            html.append(f"<li>[{f['time']}] {_esc(f['title'])} ({f['type']})</li>")
        html.append("</ul>")
    if data["moments"]:
        html.append("<h2>朋友圈(本地)</h2><ul>")
        for s in data["moments"]:
            html.append(f"<li>[{s['time']}] {_esc(s['content'])}</li>")
        html.append("</ul>")
    html.append("</body></html>")
    return ("\n".join(html)).encode("utf-8")


def export_xlsx(data):
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "消息"
    ws.append(["会话", "名称", "时间", "发送方(1=我)", "内容"])
    for m in data["messages"]:
        ws.append([m.get("talker", ""), m.get("name", ""),
                   m["time"], m["isSend"], m["content"]])
    if data["favorites"]:
        ws2 = wb.create_sheet("收藏")
        ws2.append(["时间", "标题", "类型"])
        for f in data["favorites"]:
            ws2.append([f["time"], f["title"], f["type"]])
    if data["moments"]:
        ws3 = wb.create_sheet("朋友圈")
        ws3.append(["时间", "内容"])
        for s in data["moments"]:
            ws3.append([s["time"], s["content"]])
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def export_zip(data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("messages.json", export_json(data))
        z.writestr("messages.txt", export_txt(data))
        z.writestr("messages.csv", export_csv(data))
        z.writestr("report.html", export_html(data))
        if data["favorites"] or data["moments"]:
            meta = {"favorites": len(data["favorites"]),
                    "moments": len(data["moments"])}
            z.writestr("meta.json", json.dumps(meta, ensure_ascii=False))
    return buf.getvalue()


def _esc(s):
    import html as H
    return H.escape(str(s))


DISPATCH = {
    "json": ("application/json", export_json, "export.json"),
    "txt": ("text/plain", export_txt, "export.txt"),
    "csv": ("text/csv", export_csv, "export.csv"),
    "html": ("text/html", export_html, "report.html"),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
             export_xlsx, "export.xlsx"),
    "zip": ("application/zip", export_zip, "wechat-export.zip"),
}


def build(format_name, db, talker=None, year=None):
    if format_name not in DISPATCH:
        raise ValueError("不支持的格式")
    data = collect(db, talker=talker, year=year)
    mime, fn, fname = DISPATCH[format_name]
    return mime, fn(data), fname
