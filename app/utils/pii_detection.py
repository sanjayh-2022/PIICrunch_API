import json
import re
from typing import Callable, Dict, List, Optional, Tuple

from app.utils.pii_redaction import AADHAAR_REDACTION_CATEGORIES, contains_dob

# Load patterns and keywords with error handling
try:
    with open('pii_patterns.json') as f:
        pii_patterns: Dict[str, Dict[str, List[str]]] = json.load(f)
    with open('keywords.json') as f:
        document_keywords: Dict[str, List[str]] = json.load(f)
except (FileNotFoundError, json.JSONDecodeError) as e:
    raise RuntimeError("Error loading JSON configuration files") from e


_SEPARATOR = r"[\s\-.:/]*"
_PAN_PATTERN = re.compile(
    rf"(?<![A-Z0-9])"
    rf"[A-Z]{_SEPARATOR}[A-Z]{_SEPARATOR}[A-Z]{_SEPARATOR}[A-Z]{_SEPARATOR}[A-Z]"
    rf"{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d"
    rf"{_SEPARATOR}[A-Z]"
    rf"(?![A-Z0-9])",
    re.IGNORECASE,
)
_AADHAAR_PATTERN = re.compile(
    r"(?<!\d)(?:[2-9]\d{3}[\s\-.]*\d{4}[\s\-.]*\d{4})(?![\s\-.]*\d)"
)
_VID_PATTERN = re.compile(
    r"(?<!\d)(?:\d{4}[\s\-.]*\d{4}[\s\-.]*\d{4}[\s\-.]*\d{4})(?!\d)"
)
_VOTER_ID_PATTERN = re.compile(
    rf"(?<![A-Z0-9])[A-Z]{_SEPARATOR}[A-Z]{_SEPARATOR}[A-Z]{_SEPARATOR}"
    rf"\d{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d"
    rf"(?![A-Z0-9])",
    re.IGNORECASE,
)
_DRIVING_LICENSE_PATTERN = re.compile(
    r"(?<![A-Z0-9])(?:[A-Z]{2}[\s\-.]*\d{2}[\s\-.]*\d{4}[\s\-.]*\d{7}|"
    r"[A-Z]{2}[\s\-.]*\d{13,14})(?![A-Z0-9])",
    re.IGNORECASE,
)
_PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+?91[\s\-.]*)?(?:[6-9]\d{9}|[6-9]\d{4}[\s\-.]*\d{5})(?!\d)"
)
_GENDER_PATTERN = re.compile(r"\b(?:male|female|transgender)\b", re.IGNORECASE)
_DOB_PATTERN = re.compile(
    r"(?:(?:D[\s.]*O[\s.]*B|Date\s*of\s*Birth|Birth\s*Date)[\s:.-]*)?"
    r"\b(?:0?[1-9]|[12]\d|3[01])\s*(?:[\-/\.]|\s)\s*"
    r"(?:0?[1-9]|1[0-2])\s*(?:[\-/\.]|\s)\s*(?:19|20)\d{2}\b",
    re.IGNORECASE,
)
_COMPACT_DOB_PATTERN = re.compile(
    r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])(?:19|20)\d{2}\b"
)
_ADDRESS_PATTERN = re.compile(
    r"\b(?:address|addr|add|enrolment|s/o|d/o|w/o|c/o|house|flat|street|road|village|"
    r"district|state|pin|pincode)\b[\s\S]{0,250}\b[1-9]\d{5}\b",
    re.IGNORECASE,
)
_NAME_LABEL_PATTERN = re.compile(
    r"\b(?:name|full\s*name|card\s*holder|applicant\s*name)\b\s*[:\-]?\s*[A-Z][A-Za-z .'-]{2,}",
    re.IGNORECASE,
)
_FATHER_NAME_PATTERN = re.compile(
    r"\b(?:father'?s?\s*name|father\s*/\s*guardian|s\s*/\s*o|son\s+of|d\s*/\s*o|"
    r"daughter\s+of)\b\s*[:\-]?\s*[A-Z][A-Za-z .'-]{2,}",
    re.IGNORECASE,
)
_PERSON_NAME_CANDIDATE_PATTERN = re.compile(
    r"\b[A-Z][A-Z.'-]{1,}(?:\s+[A-Z][A-Z.'-]{1,}){1,3}\b"
)
_PAN_NAME_BLOCKLIST = {
    "ACCOUNT",
    "CARD",
    "DATE",
    "DEPARTMENT",
    "DOB",
    "FATHER",
    "GOVERNMENT",
    "GOVT",
    "INDIA",
    "INCOME",
    "NAME",
    "NUMBER",
    "PAN",
    "PERMANENT",
    "SIGNATURE",
    "SON",
    "TAX",
}
_NAME_LABEL_ANY_PATTERN = re.compile(r"\b(?:name|full\s*name|card\s*holder|applicant\s*name)\b", re.IGNORECASE)
_FATHER_LABEL_ANY_PATTERN = re.compile(
    r"\b(?:father'?s?\s*name|father\s*/\s*guardian|s\s*/\s*o|son\s+of|d\s*/\s*o|daughter\s+of)\b",
    re.IGNORECASE,
)


def _bounded_numeric_match(text: str, match: re.Match[str]) -> bool:
    before = match.start() - 1
    while before >= 0 and text[before] in " \t\r\n-.":
        before -= 1
    if before >= 0 and text[before].isdigit():
        return False

    after = match.end()
    while after < len(text) and text[after] in " \t\r\n-.":
        after += 1
    return after >= len(text) or not text[after].isdigit()


def _has_aadhaar_number(text: str) -> bool:
    return any(_bounded_numeric_match(text, match) for match in _AADHAAR_PATTERN.finditer(text))


def _has_dob(text: str) -> bool:
    return contains_dob(text)


def _looks_like_pan_card(text: str) -> bool:
    text_lower = text.lower()
    return bool(_PAN_PATTERN.search(text)) or any(
        keyword in text_lower
        for keyword in ("pan", "permanent account number", "income tax department", "income tax")
    )


def _pan_name_candidates(text: str) -> List[str]:
    if not _looks_like_pan_card(text):
        return []

    candidates = []
    for match in _PERSON_NAME_CANDIDATE_PATTERN.finditer(text.upper()):
        candidate = re.sub(r"\s+", " ", match.group(0)).strip()
        words = candidate.split()
        if any(word in _PAN_NAME_BLOCKLIST for word in words):
            continue
        if any(char.isdigit() for char in candidate):
            continue
        candidates.append(candidate)

    return candidates


def _has_name(text: str) -> bool:
    if _NAME_LABEL_PATTERN.search(text) or _pan_name_candidates(text):
        return True

    return _looks_like_pan_card(text) and bool(_NAME_LABEL_ANY_PATTERN.search(text))


def _has_fathers_name(text: str) -> bool:
    if _FATHER_NAME_PATTERN.search(text) or (_looks_like_pan_card(text) and _FATHER_LABEL_ANY_PATTERN.search(text)):
        return True

    return len(_pan_name_candidates(text)) >= 2


_DETECTORS: Dict[str, Callable[[str], bool]] = {
    "Aadhaar Number": _has_aadhaar_number,
    "VID Number": lambda text: bool(_VID_PATTERN.search(text)),
    "PAN Number": lambda text: bool(_PAN_PATTERN.search(text)),
    "Voter ID Number": lambda text: bool(_VOTER_ID_PATTERN.search(text)),
    "Phone Number": lambda text: bool(_PHONE_PATTERN.search(text)),
    "Driving License Number": lambda text: bool(_DRIVING_LICENSE_PATTERN.search(text)),
    "Date of Birth": _has_dob,
    "Gender": lambda text: bool(_GENDER_PATTERN.search(text)),
    "Address": lambda text: bool(_ADDRESS_PATTERN.search(text)),
    "Name": _has_name,
    "Father's Name": _has_fathers_name,
}

_DOCUMENT_TYPE_HINTS = {
    "Aadhaar Card": {
        "pii": ("Aadhaar Number", "VID Number"),
        "keywords": ("aadhaar", "aadhar", "uidai", "unique identification", "enrolment no", "enrollment no"),
    },
    "PAN Card": {
        "pii": ("PAN Number",),
        "keywords": ("pan", "permanent account number", "income tax department", "income tax"),
    },
    "Voter ID": {
        "pii": ("Voter ID Number",),
        "keywords": ("election commission", "elector", "voter", "epic"),
    },
    "Driving License": {
        "pii": ("Driving License Number",),
        "keywords": ("driving licence", "driving license", "dl no", "licence no", "license no"),
    },
}


def _normalize_text(text: str) -> str:
    """Make OCR and DOCX/PDF text easier to scan without changing meaning."""
    if not text:
        return ""
    normalized = text.replace("\u00a0", " ")
    normalized = re.sub(r"[|]", "I", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip()


def _matches_configured_pattern(category: str, text: str) -> bool:
    patterns = pii_patterns.get(category, {}).get("regex", [])
    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                return True
        except re.error:
            continue
    return False


def _detect_categories(text: str) -> List[str]:
    detected_pii = []

    for category in pii_patterns.keys():
        detector = _DETECTORS.get(category)
        if (detector and detector(text)) or (not detector and _matches_configured_pattern(category, text)):
            detected_pii.append(category)

    for category, detector in _DETECTORS.items():
        if category not in detected_pii and detector(text):
            detected_pii.append(category)

    if (
        "Date of Birth" not in detected_pii
        and _looks_like_pan_card(text)
        and contains_dob(text)
    ):
        detected_pii.append("Date of Birth")

    return detected_pii


def _keyword_score(text_lower: str, keywords: List[str]) -> int:
    return sum(1 for keyword in keywords if keyword.lower() in text_lower)


def _detect_document_type(text: str, detected_pii: Optional[List[str]] = None) -> str:
    text_lower = text.lower()
    detected = set(detected_pii or _detect_categories(text))
    best_type = "Govt document type unidentified"
    best_score = 0

    all_doc_types = set(document_keywords) | set(_DOCUMENT_TYPE_HINTS)
    for doc_type in all_doc_types:
        score = _keyword_score(text_lower, document_keywords.get(doc_type, []))
        hints = _DOCUMENT_TYPE_HINTS.get(doc_type, {})
        score += 2 * sum(1 for keyword in hints.get("keywords", ()) if keyword in text_lower)
        score += 4 * sum(1 for pii_name in hints.get("pii", ()) if pii_name in detected)

        if score > best_score:
            best_score = score
            best_type = doc_type

    return best_type


def detect_pii(text: str) -> Tuple[List[str], str]:
    normalized_text = _normalize_text(text)
    detected_pii = _detect_categories(normalized_text)
    document_type = _detect_document_type(normalized_text, detected_pii)

    if document_type == "Aadhaar Card":
        for category in AADHAAR_REDACTION_CATEGORIES:
            if category not in detected_pii:
                detected_pii.append(category)

    return detected_pii, document_type


def detect_docType(text: str) -> str:
    """Detect document type based on keywords in the text."""
    return _detect_document_type(_normalize_text(text))
