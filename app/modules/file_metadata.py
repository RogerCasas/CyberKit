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

# Tags that contain raw binary data or large thumbnail blobs — skip them.
_SKIP_TAGS = {
    "MakerNote", "UserComment", "JPEGThumbnail", "PrintImageMatching",
    "InteropOffset", "ExifOffset", "GPSInfo",  # GPSInfo handled separately
}
_SENSITIVE_TAGS = {"GPS Latitude", "GPS Longitude", "GPS Altitude", "Author",
                   "GPSLatitude", "GPSLongitude"}


def _decode_gps_ifd(gps_ifd) -> list[MetaField]:
    """Extract GPS fields from either a plain dict or a Pillow IFD object."""
    from PIL import ExifTags  # type: ignore
    fields: list[MetaField] = []
    GPS_TAGS = ExifTags.GPSTAGS

    # Normalise: IFD objects from getexif() are iterable like dicts
    try:
        gps = {GPS_TAGS.get(k, str(k)): v for k, v in gps_ifd.items()}
    except Exception:
        return fields

    try:
        lat = _gps_to_decimal(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
        lon = _gps_to_decimal(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
        fields.append(MetaField("GPS Latitude",  str(lat), sensitive=True))
        fields.append(MetaField("GPS Longitude", str(lon), sensitive=True))
    except Exception:
        pass

    if "GPSAltitude" in gps:
        try:
            alt = _gps_to_decimal([gps["GPSAltitude"], (1, 1), (0, 1)], "N")
            fields.append(MetaField("GPS Altitude", f"{alt:.1f} m", sensitive=True))
        except Exception:
            pass

    return fields


_GPS_TAG_ID = 34853  # ExifTags.TAGS key for "GPSInfo"


def _extract_image(path: str) -> MetaResult:
    from PIL import Image, ExifTags  # type: ignore

    img = Image.open(path)
    fields: list[MetaField] = []

    # Try the modern public API first; fall back to the JPEG-specific private one.
    exif_obj = None
    try:
        exif_obj = img.getexif()
    except Exception:
        pass

    raw_exif: dict = {}
    if exif_obj:
        raw_exif = dict(exif_obj)

    # If getexif() gave nothing, try the JPEG-specific _getexif()
    if not raw_exif and hasattr(img, "_getexif"):
        try:
            got = img._getexif()
            if got:
                raw_exif = got
        except Exception:
            pass

    if not raw_exif:
        # Image opened fine but no EXIF block exists at all (common for
        # WhatsApp images — the app strips metadata before delivery).
        fields.append(MetaField(
            "Note",
            "No EXIF metadata found. Messaging apps (WhatsApp, Telegram) "
            "strip image metadata for privacy before delivery.",
            sensitive=False,
        ))
        return MetaResult(path, "image", fields)

    # Handle GPS sub-IFD — it lives at tag 34853 in both code paths but the
    # value type differs: _getexif() gives a plain dict, getexif() gives an IFD.
    gps_value = raw_exif.pop(_GPS_TAG_ID, None)
    if gps_value is not None:
        fields.extend(_decode_gps_ifd(gps_value))

    # Also check by name in case it came through differently
    for tag_id, value in raw_exif.items():
        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))

        if tag_name in _SKIP_TAGS:
            continue

        # Skip raw bytes and very long values
        if isinstance(value, bytes):
            continue
        str_value = str(value)
        if len(str_value) > 200:
            str_value = str_value[:197] + "…"

        is_sensitive = tag_name in _SENSITIVE_TAGS
        fields.append(MetaField(tag_name, str_value, sensitive=is_sensitive))

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
