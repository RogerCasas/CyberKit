"""
CyberKit — File Metadata Extractor engine

Extracts embedded metadata from images (EXIF), PDFs, and Office documents.
Never raises — errors are captured in MetaResult.error.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class MetaField:
    key:       str
    value:     str
    sensitive: bool = False   # GPS, Author, last-modified-by → True


@dataclass
class MetaResult:
    file_path: str
    file_type: str            # "image" | "pdf" | "docx" | "xlsx" | "unknown"
    fields:    list[MetaField] = field(default_factory=list)
    error:     str = ""


# ── GPS helper ────────────────────────────────────────────────────────────────

def _gps_to_decimal(rationals, ref: str) -> float:
    """Convert a (degrees, minutes, seconds) tuple of rationals to decimal degrees."""
    def _rat(r) -> float:
        if hasattr(r, "numerator"):
            return r.numerator / r.denominator if r.denominator else 0.0
        if isinstance(r, tuple) and len(r) == 2:
            return r[0] / r[1] if r[1] else 0.0
        return float(r)

    deg, mn, sec = (_rat(rationals[i]) for i in range(3))
    val = deg + mn / 60 + sec / 3600
    if ref in ("S", "W"):
        val = -val
    return round(val, 6)


# ── Image extractor ───────────────────────────────────────────────────────────

_WANTED_TAGS = {"Make", "Model", "DateTime", "Software", "Orientation"}
_SENSITIVE_TAGS = {"GPSLatitude", "GPSLongitude", "GPSAltitude", "Author"}


def _extract_image(path: str) -> MetaResult:
    from PIL import Image, ExifTags  # type: ignore

    img = Image.open(path)
    fields: list[MetaField] = []

    raw_exif = img._getexif() if hasattr(img, "_getexif") else None
    if raw_exif is None:
        try:
            raw_exif = dict(img.getexif())
        except Exception:
            raw_exif = {}

    if not raw_exif:
        return MetaResult(path, "image", fields)

    tag_names = {v: k for k, v in ExifTags.TAGS.items()}

    for tag_id, value in raw_exif.items():
        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))

        if tag_name == "GPSInfo" and isinstance(value, dict):
            GPS_TAGS = ExifTags.GPSTAGS
            gps = {GPS_TAGS.get(k, k): v for k, v in value.items()}
            try:
                lat = _gps_to_decimal(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
                lon = _gps_to_decimal(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
                fields.append(MetaField("GPS Latitude",  str(lat),             sensitive=True))
                fields.append(MetaField("GPS Longitude", str(lon),             sensitive=True))
            except Exception:
                pass
            continue

        if tag_name in _WANTED_TAGS:
            fields.append(MetaField(tag_name, str(value), sensitive=(tag_name in _SENSITIVE_TAGS)))

    return MetaResult(path, "image", fields)


# ── PDF extractor ─────────────────────────────────────────────────────────────

_PDF_SENSITIVE = {"/Author", "Author"}


def _extract_pdf(path: str) -> MetaResult:
    import pypdf  # type: ignore

    reader = pypdf.PdfReader(path)
    meta = reader.metadata or {}
    fields: list[MetaField] = []

    wanted = ["/Title", "/Author", "/Creator", "/Producer", "/CreationDate", "/ModDate"]
    for key in wanted:
        value = meta.get(key)
        if value:
            label = key.lstrip("/")
            fields.append(MetaField(label, str(value), sensitive=(key in _PDF_SENSITIVE)))

    return MetaResult(path, "pdf", fields)


# ── Office extractors ─────────────────────────────────────────────────────────

_OFFICE_SENSITIVE = {"author", "last_modified_by", "lastModifiedBy"}


def _extract_docx(path: str) -> MetaResult:
    import docx  # type: ignore

    doc = docx.Document(path)
    props = doc.core_properties
    fields: list[MetaField] = []

    _add = lambda k, v: fields.append(MetaField(k, str(v), sensitive=(k.lower().replace(" ", "_") in _OFFICE_SENSITIVE))) if v else None
    _add("Author",           props.author)
    _add("Last Modified By", props.last_modified_by)
    _add("Created",          props.created)
    _add("Modified",         props.modified)
    _add("Revision",         props.revision)
    _add("Company",          props.company)

    return MetaResult(path, "docx", fields)


def _extract_xlsx(path: str) -> MetaResult:
    import openpyxl  # type: ignore

    wb = openpyxl.load_workbook(path, read_only=True)
    props = wb.properties
    fields: list[MetaField] = []

    _add = lambda k, v: fields.append(MetaField(k, str(v), sensitive=(k.lower().replace(" ", "_") in _OFFICE_SENSITIVE))) if v else None
    _add("Author",           props.creator)
    _add("Last Modified By", props.lastModifiedBy)
    _add("Created",          props.created)
    _add("Modified",         props.modified)
    _add("Revision",         props.revision)
    _add("Company",          props.company)
    wb.close()

    return MetaResult(path, "xlsx", fields)


# ── Public API ────────────────────────────────────────────────────────────────

_IMAGE_EXT  = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp"}
_DOCX_EXT   = {".docx"}
_XLSX_EXT   = {".xlsx"}
_PDF_EXT    = {".pdf"}


def extract(path: str) -> MetaResult:
    """Extract metadata from a file. Never raises; errors appear in MetaResult.error."""
    ext = os.path.splitext(path)[1].lower()

    if ext in _IMAGE_EXT:
        extractor, ftype = _extract_image, "image"
    elif ext in _PDF_EXT:
        extractor, ftype = _extract_pdf, "pdf"
    elif ext in _DOCX_EXT:
        extractor, ftype = _extract_docx, "docx"
    elif ext in _XLSX_EXT:
        extractor, ftype = _extract_xlsx, "xlsx"
    else:
        return MetaResult(path, "unknown")

    try:
        return extractor(path)
    except Exception as exc:
        return MetaResult(path, ftype, error=str(exc))
