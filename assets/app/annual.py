# -*- coding: utf-8 -*-
"""
年度总结：把某一年的聊天数据汇总成一份只读统计报告。
"""
import datetime
from collections import defaultdict
from db import WeChatDB, word_emoji_freq


def annual_summary(db, year):
    """返回某一年的汇总 dict。"""
    msgs = db.messages_filtered(year=year)
    total = len(msgs)
    if total == 0:
        return {"year": year, "total": 0, "empty": True}

    by_day = defaultdict(int)
    by_month = defaultdict(int)
    by_talker = defaultdict(int)
    sent = 0
    recv = 0
    texts = []
    for m in msgs:
        dt = datetime.datetime.fromtimestamp(m["time"])
        key = dt.strftime("%Y-%m-%d")
        by_day[key] += 1
        by_month[dt.month] += 1
        by_talker[m["talker"]] += 1
        if m["isSend"]:
            sent += 1
        else:
            recv += 1
        if m["content"]:
            texts.append(m["content"])

    # 活跃天数
    active_days = len(by_day)
    # 最忙的一天
    busiest = max(by_day.items(), key=lambda x: x[1]) if by_day else ("", 0)
    # Top 联系人
    top_talkers = sorted(by_talker.items(), key=lambda x: -x[1])[:10]
    top_talkers = [{"talker": t, "name": db.contact_name(t), "count": c}
                   for t, c in top_talkers]
    # 月度趋势
    monthly = [by_month.get(m, 0) for m in range(1, 13)]
    # 词 / 表情
    words, emojis = word_emoji_freq(texts, top=60)
    # 时间热力
    heat = db.time_heatmap()
    # 表情 Top
    emoji_top = emojis[:20]

    return {
        "year": year,
        "total": total,
        "sent": sent,
        "recv": recv,
        "active_days": active_days,
        "busiest_day": busiest[0],
        "busiest_count": busiest[1],
        "top_talkers": top_talkers,
        "monthly": monthly,
        "words": [{"w": w, "c": c} for w, c in words[:40]],
        "emojis": [{"e": e, "c": c} for e, c in emoji_top],
        "heatmap": heat,
    }
