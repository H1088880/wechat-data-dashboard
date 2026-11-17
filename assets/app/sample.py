# -*- coding: utf-8 -*-
"""
生成一份仿微信 schema 的「已解密」示例数据库，放到 sample/ 目录，
用于在没有真实微信的机器上测试本工具。仅用于演示，不含任何个人隐私。
"""
import os
import sqlite3
import random
from datetime import datetime, timedelta

OUT = os.path.join(os.path.dirname(__file__), "sample")

CONTACTS = [
    ("wxid_file", "文件传输助手", "文件助手", "", 1),
    ("wxid_alice", "Alice王", "阿王", "alice_w", 1),
    ("wxid_bob", "老李", "李工", "bob_li", 1),
    ("wxid_mom", "妈妈", "老妈", "", 1),
    ("wxid_team", "项目攻坚群", "", "", 2),
    ("wxid_family", "一家亲", "", "", 2),
    ("wxid_zhang", "张总", "张老板", "zhang_ceo", 1),
]

# 一些中文对话片段，用于构造语料
CN_LINES = [
    "今天的需求评审会开得怎么样", "我把方案发你微信了记得看", "这个项目下周要上线压力大",
    "周末一起吃饭吧好久没聚了", "微信又更新了新版界面好看", "刚才发的红包你抢到了吗哈哈",
    "帮我看下这段代码为什么报错", "数据库的索引要加上不然慢", "明天的会议改到下午三点",
    "天气真好适合出去走走", "老板说这个季度目标要提高", "我妈让我回家吃饭了",
    "这个 bug 调了一下午终于好了", "中午吃什么想去吃火锅", "周报我写完了你那份呢",
    "视频号那个直播挺有意思的", "小程序上线了体验还可以", "收藏的那篇文章很有用",
    "晚上一起打游戏吗", "刚到家累死了先睡了", "地铁上人真多挤死了",
    "生日快乐呀🎂", "新年快乐🧧万事如意", "加油💪我们一定行", "哈哈哈哈太好笑了😂",
    "这个表情包我也想要", "收到收到马上处理", "好的没问题放心", "晚点聊先忙了",
]
EN_LINES = ["OK", "thanks", "good job", "see you", "lol", "btw check this", "done", "nice"]
EMOJIS = ["😂", "👍", "🎉", "❤️", "😊", "🤔", "🚀", "🔥", "💪", "🎂", "🧧", "🌹"]

FAV = [
    ("如何高效阅读源码", "article", "2024-03-12", "<title>如何高效阅读源码</title>..."),
    ("微信小程序开发笔记", "note", "2024-06-01", "<title>小程序开发</title>..."),
    ("一张好看的风景图", "image", "2024-09-20", "<title>风景</title>..."),
    ("年度总结模板", "file", "2024-12-30", "<title>总结</title>..."),
]

SNS = [
    ("今天去了趟海边，心情好多了🌊", "2024-07-15"),
    ("分享一篇文章：关于专注力的重要性", "2024-08-02"),
    ("周末爬了座山，累并快乐着⛰️", "2024-10-11"),
]


def gen():
    os.makedirs(OUT, exist_ok=True)
    # 先清除旧的示例库，避免主键冲突
    for fn in os.listdir(OUT):
        if fn.lower().endswith(".db"):
            p = os.path.join(OUT, fn)
            try:
                os.remove(p)
            except Exception:
                # 文件被占用时改为清空内部表（Windows 下常见）
                try:
                    c0 = sqlite3.connect(p)
                    for (t,) in c0.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"):
                        c0.execute(f'DROP TABLE IF EXISTS "{t}"')
                    c0.commit()
                    c0.close()
                except Exception:
                    pass
    # MicroMsg.db
    mm = sqlite3.connect(os.path.join(OUT, "MicroMsg.db"))
    mm.execute("""CREATE TABLE IF NOT EXISTS Contact(
        UserName TEXT, NickName TEXT, Remark TEXT, Alias TEXT, Type INTEGER)""")
    mm.executemany("INSERT INTO Contact VALUES(?,?,?,?,?)", CONTACTS)
    mm.execute("""CREATE TABLE IF NOT EXISTS ChatRoom(
        ChatRoomName TEXT, UserNameList TEXT)""")
    mm.execute("INSERT INTO ChatRoom VALUES(?,?)",
               ("wxid_team", "wxid_alice,wxid_bob,wxid_zhang"))
    mm.execute("INSERT INTO ChatRoom VALUES(?,?)",
               ("wxid_family", "wxid_mom,wxid_alice"))
    mm.commit()
    mm.close()

    # Msg.db
    msg = sqlite3.connect(os.path.join(OUT, "Msg.db"))
    msg.execute("""CREATE TABLE IF NOT EXISTS MSG(
        MsgSvrID INTEGER PRIMARY KEY, type INTEGER, strTalker TEXT,
        strContent TEXT, createTime INTEGER, IsSender INTEGER)""")
    base = datetime(2024, 1, 1, 8, 0, 0)
    rows = []
    mid = 1
    talkers = [c[0] for c in CONTACTS]
    for day in range(365):
        d = base + timedelta(days=day)
        # 每个会话每天随机若干条
        for tk in talkers:
            n = random.randint(0, 6)
            for _ in range(n):
                ts = d + timedelta(hours=random.randint(7, 23),
                                   minutes=random.randint(0, 59))
                is_send = random.randint(0, 1)
                pool = CN_LINES + EN_LINES
                content = random.choice(pool)
                if random.random() < 0.15:
                    content += " " + random.choice(EMOJIS)
                rows.append((mid, 1, tk, content,
                             int(ts.timestamp()), is_send))
                mid += 1
    msg.executemany("INSERT INTO MSG VALUES(?,?,?,?,?,?)", rows)
    msg.commit()
    msg.close()

    # Favorite.db
    fav = sqlite3.connect(os.path.join(OUT, "Favorite.db"))
    fav.execute("""CREATE TABLE IF NOT EXISTS Favorite(
        FavId INTEGER, strTitle TEXT, type TEXT, sourceTime TEXT, strXml TEXT)""")
    for i, (title, t, tm, xml) in enumerate(FAV, 1):
        fav.execute("INSERT INTO Favorite VALUES(?,?,?,?,?)", (i, title, t, tm, xml))
    fav.commit()
    fav.close()

    # Sns.db
    sns = sqlite3.connect(os.path.join(OUT, "Sns.db"))
    sns.execute("""CREATE TABLE IF NOT EXISTS SnsInfo(
        SnsId INTEGER, strContent TEXT, createTime INTEGER)""")
    for i, (c, tm) in enumerate(SNS, 1):
        ts = int(datetime.strptime(tm, "%Y-%m-%d").timestamp())
        sns.execute("INSERT INTO SnsInfo VALUES(?,?,?)", (i, c, ts))
    sns.commit()
    sns.close()

    print("sample data generated at", OUT)
    print("messages:", len(rows), "contacts:", len(CONTACTS))


if __name__ == "__main__":
    gen()
