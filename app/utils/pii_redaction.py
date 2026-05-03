import re
from typing import Iterable, List, Optional, Set


ALL_PII_CATEGORIES = {
    "Aadhaar Number",
    "VID Number",
    "PAN Number",
    "Voter ID Number",
    "Phone Number",
    "Driving License Number",
    "Date of Birth",
    "Gender",
    "Address",
    "Name",
    "Father's Name",
}

AADHAAR_REDACTION_CATEGORIES = (
    "Aadhaar Number",
    "VID Number",
    "Date of Birth",
    "Gender",
    "Address",
    "Name",
    "Father's Name",
    "Phone Number",
)

VOTER_ID_REDACTION_CATEGORIES = (
    "Voter ID Number",
    "Name",
    "Father's Name",
    "Date of Birth",
    "Gender",
    "Address",
)

DRIVING_LICENSE_REDACTION_CATEGORIES = (
    "Driving License Number",
    "Name",
    "Father's Name",
    "Date of Birth",
    "Address",
)

DOCUMENT_REDACTION_CATEGORIES = {
    "Aadhaar Card": AADHAAR_REDACTION_CATEGORIES,
    "Voter ID": VOTER_ID_REDACTION_CATEGORIES,
    "Driving License": DRIVING_LICENSE_REDACTION_CATEGORIES,
}

_SEPARATOR = r"[\s\-.:/]*"

PAN_PATTERN = re.compile(
    rf"(?<![A-Z0-9])"
    rf"[A-Z]{_SEPARATOR}[A-Z]{_SEPARATOR}[A-Z]{_SEPARATOR}[A-Z]{_SEPARATOR}[A-Z]"
    rf"{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d"
    rf"{_SEPARATOR}[A-Z]"
    rf"(?![A-Z0-9])",
    re.IGNORECASE,
)
AADHAAR_PATTERN = re.compile(
    r"(?<!\d)(?:[2-9]\d{3}[\s\-.]*\d{4}[\s\-.]*\d{4})(?![\s\-.]*\d)"
)
VID_PATTERN = re.compile(
    r"(?<!\d)(?:\d{4}[\s\-.]*\d{4}[\s\-.]*\d{4}[\s\-.]*\d{4})(?![\s\-.]*\d)"
)
VOTER_ID_PATTERN = re.compile(
    rf"(?<![A-Z0-9])[A-Z]{_SEPARATOR}[A-Z]{_SEPARATOR}[A-Z]{_SEPARATOR}"
    rf"\d{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d{_SEPARATOR}\d"
    rf"(?![A-Z0-9])",
    re.IGNORECASE,
)
DRIVING_LICENSE_PATTERN = re.compile(
    r"(?<![A-Z0-9])(?:[A-Z]{2}[\s\-.]*\d{2}[\s\-.]*\d{4}[\s\-.]*\d{7}|"
    r"[A-Z]{2}[\s\-.]*\d{13,14})(?![A-Z0-9])",
    re.IGNORECASE,
)
PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+?91[\s\-.]*)?(?:[6-9]\d{9}|[6-9]\d{4}[\s\-.]*\d{5})(?!\d)"
)
GENDER_PATTERN = re.compile(r"\b(?:male|female|transgender)\b", re.IGNORECASE)
DOB_PATTERN = re.compile(
    r"(?:(?:D[\s.]*O[\s.]*B|Date\s*of\s*Birth(?:\s*/\s*Incorporation)?|Birth\s*Date)[\s:/.-]*)?"
    r"\b(?:0?[1-9]|[12]\d|3[01])\s*(?:[\-/\.]|\s)\s*"
    r"(?:0?[1-9]|1[0-2])\s*(?:[\-/\.]|\s)\s*(?:19|20)\d{2}\b",
    re.IGNORECASE,
)
DATE_LABEL_ONLY_PATTERN = re.compile(
    r"\b(?:D[\s.]*O[\s.]*B|Date\s*of\s*Birth(?:\s*/\s*Incorporation)?|Birth\s*Date)\b\s*[:/\-]?\s*$",
    re.IGNORECASE,
)
DATE_LABEL_PATTERN = re.compile(
    r"\b(?:D[\s.]*O[\s.]*B|Date\s*of\s*Birth(?:\s*/\s*Incorporation)?|Birth\s*Date)\b",
    re.IGNORECASE,
)
COMPACT_DOB_PATTERN = re.compile(
    r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])(?:19|20)\d{2}\b"
)
DATE_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:[0-9OoIl|SsBb][0-9OoIl|SsBb\s\-/.]{4,18}[0-9OoIl|SsBb])(?![A-Za-z0-9])"
)
SEPARATED_DATE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    r"[0-9OoIl|SsBb]{1,2}\s*[/\\\-.]\s*"
    r"[0-9OoIl|SsBb]{1,2}\s*[/\\\-.]\s*"
    r"(?:[12Il|][0-9OoIl|SsBb]{3})"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)
ADDRESS_PATTERN = re.compile(
    r"\b(?:address|addr|add|enrolment|enrollment|s/o|d/o|w/o|c/o|house|flat|street|road|"
    r"village|district|state|pin|pincode)\b[\s\S]{0,250}\b[1-9]\d{5}\b",
    re.IGNORECASE,
)
NAME_LABEL_PATTERN = re.compile(
    r"\b(?:name|full\s*name|card\s*holder|applicant\s*name)\b\s*[:\-]?\s*[A-Z][A-Za-z .'-]{2,}",
    re.IGNORECASE,
)
NAME_LABEL_ONLY_PATTERN = re.compile(
    r"\b(?:name|full\s*name|card\s*holder|applicant\s*name)\b\s*[:\-]?\s*$",
    re.IGNORECASE,
)
FATHER_NAME_PATTERN = re.compile(
    r"\b(?:father'?s?\s*name|father\s*/\s*guardian|s\s*/\s*o|son\s+of|d\s*/\s*o|"
    r"daughter\s+of)\b\s*[:\-]?\s*[A-Z][A-Za-z .'-]{2,}",
    re.IGNORECASE,
)
FATHER_LABEL_ONLY_PATTERN = re.compile(
    r"\b(?:father'?s?\s*name|father\s*/\s*guardian|s\s*/\s*o|son\s+of|d\s*/\s*o|"
    r"daughter\s+of)\b\s*[:\-]?\s*$",
    re.IGNORECASE,
)

_NAME_BLOCKLIST = {
    "AADHAAR",
    "AADHAR",
    "ACCOUNT",
    "ADDRESS",
    "AUTHORITY",
    "BIRTH",
    "CARD",
    "DATE",
    "DEPARTMENT",
    "DOB",
    "FEMALE",
    "FATHER",
    "GOVERNMENT",
    "GOVT",
    "IDENTIFICATION",
    "INCOME",
    "INDIA",
    "MALE",
    "NAME",
    "NUMBER",
    "PAN",
    "PERMANENT",
    "SIGNATURE",
    "SON",
    "TAX",
    "UNIQUE",
    "VID",
}


def normalize_categories(categories: Optional[Iterable[str]]) -> Set[str]:
    if not categories:
        return set(ALL_PII_CATEGORIES)

    normalized = {category.strip() for category in categories if category and category.strip()}
    return normalized or set(ALL_PII_CATEGORIES)


def expand_categories_for_document(categories: Optional[Iterable[str]], document_type: str = "") -> Set[str]:
    normalized = normalize_categories(categories)
    if document_type in DOCUMENT_REDACTION_CATEGORIES:
        normalized.update(DOCUMENT_REDACTION_CATEGORIES[document_type])
    if {"Aadhaar Number", "VID Number"} & normalized:
        normalized.update(AADHAAR_REDACTION_CATEGORIES)
    if "Voter ID Number" in normalized:
        normalized.update(VOTER_ID_REDACTION_CATEGORIES)
    if "Driving License Number" in normalized:
        normalized.update(DRIVING_LICENSE_REDACTION_CATEGORIES)
    if "PAN Number" in normalized:
        normalized.add("Date of Birth")
    return normalized


def digits_only(text: str) -> str:
    return re.sub(r"\D", "", text or "")


_OCR_DIGIT_TRANSLATION = str.maketrans({
    "O": "0",
    "o": "0",
    "I": "1",
    "i": "1",
    "l": "1",
    "|": "1",
    "S": "5",
    "s": "5",
    "B": "8",
    "b": "8",
})


def normalize_ocr_digits(text: str) -> str:
    return (text or "").translate(_OCR_DIGIT_TRANSLATION)


def ocr_digits_only(text: str) -> str:
    return digits_only(normalize_ocr_digits(text))


def is_valid_dob_digits(digits: str) -> bool:
    if len(digits) != 8:
        return False

    day = int(digits[:2])
    month = int(digits[2:4])
    year = int(digits[4:])
    return 1 <= day <= 31 and 1 <= month <= 12 and 1900 <= year <= 2099


def _bounded_numeric_match(text: str, match: re.Match) -> bool:
    before = match.start() - 1
    while before >= 0 and text[before] in " \t\r\n-.":
        before -= 1
    if before >= 0 and text[before].isdigit():
        return False

    after = match.end()
    while after < len(text) and text[after] in " \t\r\n-.":
        after += 1
    return after >= len(text) or not text[after].isdigit()


def contains_aadhaar(text: str) -> bool:
    return any(_bounded_numeric_match(text, match) for match in AADHAAR_PATTERN.finditer(text or ""))


def contains_vid(text: str) -> bool:
    return bool(VID_PATTERN.search(text or ""))


def contains_dob(text: str) -> bool:
    normalized_text = normalize_ocr_digits(text)
    if DOB_PATTERN.search(normalized_text) or COMPACT_DOB_PATTERN.search(normalized_text):
        return True

    return any(
        is_valid_dob_digits(ocr_digits_only(match.group(0)))
        for pattern in (SEPARATED_DATE_PATTERN, DATE_CANDIDATE_PATTERN)
        for match in pattern.finditer(text or "")
    )


def contains_category(category: str, text: str) -> bool:
    text = text or ""
    if category == "Aadhaar Number":
        return contains_aadhaar(text)
    if category == "VID Number":
        return contains_vid(text)
    if category == "PAN Number":
        return bool(PAN_PATTERN.search(text))
    if category == "Voter ID Number":
        return bool(VOTER_ID_PATTERN.search(text))
    if category == "Phone Number":
        return bool(PHONE_PATTERN.search(text))
    if category == "Driving License Number":
        return bool(DRIVING_LICENSE_PATTERN.search(text))
    if category == "Date of Birth":
        return contains_dob(text)
    if category == "Gender":
        return bool(GENDER_PATTERN.search(text))
    if category == "Address":
        return bool(ADDRESS_PATTERN.search(text))
    if category == "Name":
        return bool(NAME_LABEL_PATTERN.search(text))
    if category == "Father's Name":
        return bool(FATHER_NAME_PATTERN.search(text))
    return False


def has_identity_context(document_type: str, full_text: str) -> bool:
    text_lower = (full_text or "").lower()
    return (
        document_type in {"Aadhaar Card", "PAN Card", "Voter ID", "Driving License"}
        or contains_aadhaar(full_text)
        or bool(PAN_PATTERN.search(full_text or ""))
        or any(
            keyword in text_lower
            for keyword in (
                "aadhaar",
                "aadhar",
                "uidai",
                "permanent account number",
                "income tax",
                "election commission",
                "driving licence",
                "driving license",
            )
        )
    )


def is_name_candidate(text: str) -> bool:
    cleaned = re.sub(r"\s+", " ", (text or "").strip(" :-|"))
    if not cleaned or len(cleaned) > 70:
        return False
    if re.fullmatch(r"[Xx\s/.-]+", cleaned):
        return False
    if any(char.isdigit() for char in cleaned):
        return False
    if PAN_PATTERN.search(cleaned) or DOB_PATTERN.search(cleaned):
        return False

    words = re.findall(r"[A-Za-z][A-Za-z.'-]*", cleaned)
    if len(words) < 2 or len(words) > 5:
        return False
    if not all(word[0].isupper() for word in words):
        return False
    if any(word.upper().strip(".'-") in _NAME_BLOCKLIST for word in words):
        return False

    letters = re.sub(r"[^A-Za-z]", "", cleaned)
    return len(letters) >= 5


def _sub_bounded(pattern: re.Pattern, text: str, replacement: str) -> str:
    pieces = []
    last_index = 0
    for match in pattern.finditer(text):
        if not _bounded_numeric_match(text, match):
            continue
        pieces.append(text[last_index:match.start()])
        pieces.append(replacement)
        last_index = match.end()

    if not pieces:
        return text

    pieces.append(text[last_index:])
    return "".join(pieces)


def _redact_date_candidates(text: str) -> str:
    def replace_valid_date(match: re.Match) -> str:
        candidate = match.group(0)
        normalized_candidate = normalize_ocr_digits(candidate)
        is_date = (
            DOB_PATTERN.search(normalized_candidate)
            or COMPACT_DOB_PATTERN.search(normalized_candidate)
            or is_valid_dob_digits(ocr_digits_only(candidate))
        )
        return "XX/XX/XXXX" if is_date else candidate

    redacted = SEPARATED_DATE_PATTERN.sub(replace_valid_date, text)
    return DATE_CANDIDATE_PATTERN.sub(replace_valid_date, redacted)


def _redact_labelled_names(text: str, categories: Set[str]) -> str:
    if "Name" in categories:
        text = re.sub(
            r"\b(Name|Full\s*Name|Card\s*Holder|Applicant\s*Name)\b\s*[:\-]?\s*"
            r"[A-Z][A-Za-z .'-]{2,}?"
            r"(?=\s+(?:Father'?s?\s*Name|Father\s*/\s*Guardian|S\s*/\s*O|Son\s+of|"
            r"D[\s.]*O[\s.]*B|Date\s*of\s*Birth|Birth\s*Date|Address|Male|Female)\b|$)",
            lambda match: f"{match.group(1)} XXXX",
            text,
            flags=re.IGNORECASE,
        )

    if "Father's Name" in categories:
        text = re.sub(
            r"\b(Father'?s?\s*Name|Father\s*/\s*Guardian|S\s*/\s*O|Son\s+of|D\s*/\s*O|Daughter\s+of)\b"
            r"\s*[:\-]?\s*[A-Z][A-Za-z .'-]{2,}?"
            r"(?=\s+(?:D[\s.]*O[\s.]*B|Date\s*of\s*Birth|Birth\s*Date|Address|Male|Female)\b|$)",
            lambda match: f"{match.group(1)} XXXX",
            text,
            flags=re.IGNORECASE,
        )

    return text


def _redact_contextual_name_lines(text: str, categories: Set[str], document_type: str) -> str:
    if not ({"Name", "Father's Name"} & categories) or not has_identity_context(document_type, text):
        return text

    lines = text.splitlines(keepends=True)
    if len(lines) <= 1:
        return "XXXX" if is_name_candidate(text) else text

    redacted_lines: List[str] = []
    for line in lines:
        line_body = line.rstrip("\r\n")
        line_end = line[len(line_body):]
        if is_name_candidate(line_body):
            redacted_lines.append("XXXX" + line_end)
        else:
            redacted_lines.append(line)

    return "".join(redacted_lines)


def redact_text(text: str, categories: Optional[Iterable[str]] = None, document_type: str = "") -> str:
    categories_set = expand_categories_for_document(categories, document_type)
    redacted = text or ""

    redacted = _redact_labelled_names(redacted, categories_set)

    if "VID Number" in categories_set:
        redacted = VID_PATTERN.sub("XXXX XXXX XXXX XXXX", redacted)
    if "Phone Number" in categories_set:
        redacted = PHONE_PATTERN.sub("XXXXXX", redacted)
    if "Aadhaar Number" in categories_set:
        redacted = _sub_bounded(AADHAAR_PATTERN, redacted, "XXXX XXXX XXXX")
    if "PAN Number" in categories_set:
        redacted = PAN_PATTERN.sub("XXXXXX", redacted)
    if "Voter ID Number" in categories_set:
        redacted = VOTER_ID_PATTERN.sub("XXXXXX", redacted)
    if "Driving License Number" in categories_set:
        redacted = DRIVING_LICENSE_PATTERN.sub("XXXXXX", redacted)
    if "Date of Birth" in categories_set:
        redacted = _redact_date_candidates(redacted)
    if "Gender" in categories_set:
        redacted = GENDER_PATTERN.sub("XXXX", redacted)
    if "Address" in categories_set:
        redacted = ADDRESS_PATTERN.sub("XXXX", redacted)

    return _redact_contextual_name_lines(redacted, categories_set, document_type)
