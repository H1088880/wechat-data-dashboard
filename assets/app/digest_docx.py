# -*- coding: utf-8 -*-
"""
零依赖 Word(.docx) 生成器 —— 仅用标准库 zipfile 构造最小合法的 OOXML 文档。

不依赖 python-docx，跨平台开箱即用。支持：标题、段落、分页友好的结构化文本、
自动转义 XML 特殊字符、中文正常显示。

作者署名：云帆-H1088880
"""
import zipfile
import html
from datetime import datetime

_NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""

_DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="%s">
  <w:docDefaults><w:rPrDefault><w:rPr>
    <w:rFonts w:ascii="Microsoft YaHei" w:hAnsi="Microsoft YaHei" w:eastAsia="Microsoft YaHei"/>
    <w:sz w:val="21"/><w:szCs w:val="21"/>
  </w:rPr></w:rPrDefault></w:docDefaults>
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:pPr><w:jc w:val="center"/></w:pPr>
    <w:rPr><w:b/><w:sz w:val="36"/><w:szCs w:val="36"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/>
    <w:rPr><w:b/><w:sz w:val="28"/><w:szCs w:val="28"/><w:color w:val="1F6F4A"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/>
    <w:rPr><w:b/><w:sz w:val="24"/><w:szCs w:val="24"/><w:color w:val="2E74B5"/></w:rPr></w:style>
</w:styles>""" % _NS_W


def _esc(s):
    return html.escape(str(s), quote=False)


def _para(text="", style="Normal", bold=False, color=None, size=None):
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style != "Normal" else ""
    rpr = ""
    if bold or color or size:
        parts = []
        if bold:
            parts.append("<w:b/>")
        if color:
            parts.append(f'<w:color w:val="{color}"/>')
        if size:
            parts.append(f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>')
        rpr = "<w:rPr>" + "".join(parts) + "</w:rPr>"
    # 支持换行
    runs = str(text).split("\n")
    body = []
    for i, line in enumerate(runs):
        if i:
            body.append("<w:r><w:br/></w:r>")
        body.append(f"<w:r>{rpr}<w:t xml:space='preserve'>{_esc(line)}</w:t></w:r>")
    return f"<w:p>{ppr}{''.join(body)}</w:p>"


def build_document(title, blocks):
    """生成 docx 字节。

    blocks: list of dict，支持类型：
      {'t':'h1','text':...}      一级标题
      {'t':'h2','text':...}      二级标题
      {'t':'p','text':...}       正文段落
      {'t':'item','label':..., 'text':...}  一条记录（label 加粗）
      {'t':'hr'}                分隔线
      {'t':'blank'}             空行
    """
    parts = [_para(title, style="Title")]
    for b in blocks:
        t = b.get("t")
        if t == "h1":
            parts.append(_para(b.get("text", ""), style="Heading1"))
        elif t == "h2":
            parts.append(_para(b.get("text", ""), style="Heading2"))
        elif t == "p":
            parts.append(_para(b.get("text", "")))
        elif t == "item":
            label = b.get("label", "")
            text = b.get("text", "")
            body = f'<w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">{_esc(label)}</w:t></w:r>'
            body += f'<w:r><w:t xml:space="preserve">{_esc(text)}</w:t></w:r>'
            parts.append(f"<w:p>{body}</w:p>")
        elif t == "hr":
            parts.append('<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="6" w:color="CCCCCC"/></w:pBdr></w:pPr></w:p>')
        elif t == "blank":
            parts.append("<w:p/>")
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{_NS_W}"><w:body>'
        + "".join(parts)
        + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1080" w:bottom="1440" w:left="1080" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>'
        '</w:body></w:document>'
    )

    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f'<dc:title>{_esc(title)}</dc:title><dc:creator>云帆-H1088880</dc:creator>'
        f'<cp:lastModifiedBy>云帆-H1088880</cp:lastModifiedBy><dcterms:created xmlns:dcterms="http://purl.org/dc/terms/" '
        f'xsi:type="dcterms:W3CDTF" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">{now}</dcterms:created>'
        '</cp:coreProperties>'
    )
    app = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        '<Application>WeChat Dashboard</Application></Properties>'
    )

    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _ROOT_RELS)
        z.writestr("word/document.xml", document)
        z.writestr("word/styles.xml", _STYLES)
        z.writestr("word/_rels/document.xml.rels", _DOC_RELS)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
    return buf.getvalue()


if __name__ == "__main__":
    data = build_document("测试文档", [
        {"t": "h1", "text": "第一节"},
        {"t": "item", "label": "张三 12:00 ", "text": "这是一条测试消息"},
        {"t": "p", "text": "署名 云帆-H1088880"},
    ])
    open("_test.docx", "wb").write(data)
    print("生成 _test.docx", len(data), "bytes")
