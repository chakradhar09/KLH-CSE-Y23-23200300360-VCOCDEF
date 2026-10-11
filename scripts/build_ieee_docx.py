#!/usr/bin/env python3
"""Fill the IEEE two-column .docx template with the text of Doc/Research_Paper_v3.md.

Keeps the template's title block, author table, page setup and two-column body section, and reuses its direct
formatting for headings, body text, tables, captions and references. Standard library only.
"""
from __future__ import annotations

import argparse
import re
import struct
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
COL_DXA = 4699  # width of one column in the template, as its own Table I uses
COL_EMU = 2900000  # picture width: one column, a little inset
HEADER_FILL = "D9E2F3"


def run(text: str, b=False, i=False, code=False, sz: int | None = None) -> str:
    props = ""
    if code:
        props += '<w:rFonts w:ascii="Courier New" w:hAnsi="Courier New" w:cs="Courier New"/>'
    if b:
        props += "<w:b/><w:bCs/>"
    if i:
        props += "<w:i/><w:iCs/>"
    if sz:
        props += f'<w:sz w:val="{sz}"/><w:szCs w:val="{sz}"/>'
    rpr = f"<w:rPr>{props}</w:rPr>" if props else ""
    return f'<w:r>{rpr}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'


TOKEN = re.compile(r"(\*\*.+?\*\*|`.+?`|\*[^*\s][^*]*?\*)")


def inline(text: str, sz: int | None = None, bold=False, italic=False) -> str:
    out = []
    code_sz = (sz - 1 if sz else 18)
    for part in TOKEN.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            out.append(run(part[2:-2], b=True, i=italic, sz=sz))
        elif part.startswith("`") and part.endswith("`"):
            out.append(run(part[1:-1].replace("_", "_​"), b=bold, i=italic, code=True, sz=code_sz))  # break after _
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            out.append(run(part[1:-1], b=bold, i=True, sz=sz))
        else:
            out.append(run(part, b=bold, i=italic, sz=sz))
    return "".join(out)


def para(ppr: str, runs: str) -> str:
    return f"<w:p><w:pPr>{ppr}</w:pPr>{runs}</w:p>"


def body(text: str) -> str:
    return para('<w:spacing w:after="120"/><w:jc w:val="both"/>', inline(text))


def heading1(text: str) -> str:
    return para(
        '<w:pStyle w:val="Heading1"/><w:spacing w:before="240" w:after="120"/><w:jc w:val="center"/>',
        '<w:r><w:rPr><w:b/><w:bCs/><w:color w:val="000000"/><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr>'
        f'<w:t xml:space="preserve">{escape(text.upper())}</w:t></w:r>',
    )


def heading2(text: str) -> str:
    return para(
        '<w:spacing w:before="160" w:after="80"/>',
        '<w:r><w:rPr><w:b/><w:bCs/><w:i/><w:iCs/><w:color w:val="000000"/></w:rPr>'
        f'<w:t xml:space="preserve">{escape(text)}</w:t></w:r>',
    )


def bullet(text: str) -> str:
    return para(
        '<w:pStyle w:val="ListParagraph"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr>'
        '<w:spacing w:after="80"/><w:jc w:val="both"/>',
        inline(text),
    )


def numbered(text: str) -> str:
    return para('<w:spacing w:after="80"/><w:ind w:left="260" w:hanging="260"/><w:jc w:val="both"/>', inline(text))


def reference(text: str) -> str:
    return para('<w:spacing w:after="100"/><w:ind w:left="260" w:hanging="260"/><w:jc w:val="both"/>', inline(text))


def caption(text: str) -> str:
    return para('<w:spacing w:before="80" w:after="160"/><w:jc w:val="center"/>', run(text, i=True, sz=18))


def split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def table(lines: list[str]) -> str:
    header = split_row(lines[0])
    align = []
    for c in split_row(lines[1]):
        align.append("center" if c.startswith(":") and c.endswith(":") else "right" if c.endswith(":") else "left")
    rows = [split_row(r) for r in lines[2:]]
    n = len(header)
    sz = 16 if n <= 5 else 14
    times_w, code_w, pad = sz * 4.75, (sz - 1) * 6.0, 130  # rough dxa per character; cell margins
    need, avg = [], []
    for k in range(n):
        longest = 0.0
        for row, is_head in [(header, True)] + [(r, False) for r in rows]:
            for part in re.split(r"(`[^`]+`)", row[k].replace("**", "")):
                if part.startswith("`"):
                    longest = max(longest, min(len(part) - 2, 10) * code_w)  # long code names may break
                else:
                    longest = max([longest] + [len(w) * times_w * (1.1 if is_head else 1) for w in part.split()])
        need.append(longest + pad)
        avg.append(sum(len(r[k]) for r in rows) / len(rows) + 1)
    if sum(need) > COL_DXA:  # cannot fit unbroken: shrink evenly and let the widest words wrap
        need = [x * COL_DXA / sum(need) for x in need]
    spare = COL_DXA - sum(need)
    widths = [int(x + spare * a / sum(avg)) for x, a in zip(need, avg)]
    widths[widths.index(max(widths))] += COL_DXA - sum(widths)

    mar = (
        '<w:tcMar><w:top w:w="40" w:type="dxa"/><w:left w:w="60" w:type="dxa"/>'
        '<w:bottom w:w="40" w:type="dxa"/><w:right w:w="60" w:type="dxa"/></w:tcMar><w:vAlign w:val="center"/>'
    )

    def cell(text: str, k: int, head: bool) -> str:
        shd = f'<w:shd w:val="clear" w:color="auto" w:fill="{HEADER_FILL}"/>' if head else ""
        jc = "center" if head else align[k]
        jc_xml = f'<w:jc w:val="{jc}"/>' if jc != "left" else ""
        return (
            f'<w:tc><w:tcPr><w:tcW w:w="{widths[k]}" w:type="dxa"/>{shd}{mar}</w:tcPr>'
            f"<w:p><w:pPr>{jc_xml}</w:pPr>{inline(text, sz=sz, bold=head)}</w:p></w:tc>"
        )

    borders = "".join(
        f'<w:{s} w:val="single" w:sz="4" w:space="0" w:color="auto"/>'
        for s in ("top", "left", "bottom", "right", "insideH", "insideV")
    )
    out = [
        f'<w:tbl><w:tblPr><w:tblW w:w="{COL_DXA}" w:type="dxa"/><w:tblBorders>{borders}</w:tblBorders>'
        '<w:tblLayout w:type="fixed"/><w:tblCellMar><w:left w:w="10" w:type="dxa"/><w:right w:w="10" w:type="dxa"/></w:tblCellMar>'
        '<w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="1" w:lastColumn="0" w:noHBand="0" w:noVBand="1"/>'
        "</w:tblPr><w:tblGrid>" + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + "</w:tblGrid>"
    ]
    out.append("<w:tr><w:trPr><w:cantSplit/><w:tblHeader/></w:trPr>" + "".join(cell(h, k, True) for k, h in enumerate(header)) + "</w:tr>")
    for r in rows:
        out.append("<w:tr><w:trPr><w:cantSplit/></w:trPr>" + "".join(cell(c, k, False) for k, c in enumerate(r)) + "</w:tr>")
    out.append("</w:tbl>")
    return "".join(out)


def png_size(path: Path) -> tuple[int, int]:
    with open(path, "rb") as f:
        head = f.read(24)
    return struct.unpack(">II", head[16:24])


def figure(alt: str, rid: str, path: Path, pic_id: int) -> str:
    w, h = png_size(path)
    cx, cy = COL_EMU, int(COL_EMU * h / w)
    name = escape(alt, {'"': "&quot;"})
    drawing = (
        f'<w:r><w:rPr><w:noProof/></w:rPr><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">'
        f'<wp:extent cx="{cx}" cy="{cy}"/><wp:effectExtent l="0" t="0" r="0" b="0"/>'
        f'<wp:docPr id="{pic_id}" name="{name}" descr="{name}"/>'
        '<wp:cNvGraphicFramePr><a:graphicFrameLocks xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" noChangeAspect="1"/></wp:cNvGraphicFramePr>'
        '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '<pic:nvPicPr><pic:cNvPr id="0" name=""/><pic:cNvPicPr><a:picLocks noChangeAspect="1" noChangeArrowheads="1"/></pic:cNvPicPr></pic:nvPicPr>'
        f'<pic:blipFill><a:blip r:embed="{rid}"/><a:srcRect/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
        f'<pic:spPr bwMode="auto"><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic>'
        "</wp:inline></w:drawing></w:r>"
    )
    return para('<w:keepNext/><w:spacing w:before="120" w:after="40"/><w:jc w:val="center"/>', drawing) + caption(alt)


def convert(md: str, media: list[tuple[str, Path]]) -> str:
    start = md.index("**Abstract")
    blocks = re.split(r"\n\s*\n", md[start:].strip())
    out = []
    for blk in blocks:
        lines = [l for l in blk.split("\n") if l.strip()]
        first = lines[0]
        if first.startswith("# "):
            out.append(heading1(first[2:].strip()))
        elif first.startswith("## "):
            out.append(heading2(first[3:].strip()))
        elif first.startswith("|"):
            out.append(table(lines))
        elif first.startswith("!["):
            m = re.match(r"!\[(.*)\]\((.*?)\)", first)
            alt, rel = m.group(1), ROOT / m.group(2)
            rid = f"rIdFig{len(media) + 1}"
            media.append((rid, rel))
            out.append(figure(alt, rid, rel, 100 + len(media)))
        elif re.match(r"^\*Table [^*]*\*$", first):
            out.append(caption(first.strip("*")))
        elif re.match(r"^\[\d+\] ", first):
            out.extend(reference(l) for l in lines)
        elif first.startswith("- "):
            out.extend(bullet(l[2:]) for l in lines)
        elif re.match(r"^\d+\. ", first):
            out.extend(numbered(l) for l in lines)
        else:
            out.append(body(" ".join(l.strip() for l in lines)))
    return "".join(out)


def build(template: Path, md_path: Path, out_path: Path) -> None:
    with zipfile.ZipFile(template) as z:
        parts = {n: z.read(n) for n in z.namelist()}
        order = z.namelist()

    doc = parts["word/document.xml"].decode("utf-8")
    head_end = doc.index("</w:p>", doc.index("<w:sectPr")) + len("</w:p>")  # end of the one-column title section
    tail = doc[doc.rindex("<w:sectPr"):]  # the two-column section properties
    media: list[tuple[str, Path]] = []
    content = convert(md_path.read_text(encoding="utf-8"), media)
    parts["word/document.xml"] = (doc[:head_end] + content + tail).encode("utf-8")

    rels = parts["word/_rels/document.xml.rels"].decode("utf-8")
    rels = re.sub(r'<Relationship Id="rId[567]"[^>]*image[^>]*/>', "", rels)  # the template's old figures
    for name in [n for n in order if n.startswith("word/media/")]:
        del parts[name]
    order = [n for n in order if n in parts]
    for k, (rid, path) in enumerate(media, start=1):
        target = f"media/paper_fig{k}.png"
        rels = rels.replace(
            "</Relationships>",
            f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{target}"/></Relationships>',
        )
        parts["word/" + target] = path.read_bytes()
        order.append("word/" + target)
    parts["word/_rels/document.xml.rels"] = rels.encode("utf-8")

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        for n in order:
            z.writestr(n, parts[n])


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--template", default=str(ROOT / "Doc" / "Research_Paper_IEEE_Format.docx"))
    ap.add_argument("--md", default=str(ROOT / "Doc" / "Research_Paper_v3.md"))
    ap.add_argument("--out", default=str(ROOT / "Doc" / "Research_Paper_v3_IEEE.docx"))
    a = ap.parse_args()
    build(Path(a.template), Path(a.md), Path(a.out))
    print("wrote", a.out)
