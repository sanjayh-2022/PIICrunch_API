import re
from typing import Iterable, List, Set

import cv2

from app.utils.pii_redaction import (
    ALL_PII_CATEGORIES,
    DATE_LABEL_ONLY_PATTERN,
    DATE_LABEL_PATTERN,
    FATHER_LABEL_ONLY_PATTERN,
    FATHER_NAME_PATTERN,
    NAME_LABEL_ONLY_PATTERN,
    NAME_LABEL_PATTERN,
    contains_category,
    contains_dob,
    digits_only,
    expand_categories_for_document,
    has_identity_context,
    is_valid_dob_digits,
    is_name_candidate,
    ocr_digits_only,
)


def mask_text(image, bbox):
    """Mask the whole OCR bounding box."""
    xs = [point[0] for point in bbox]
    ys = [point[1] for point in bbox]
    top_left = (int(min(xs)), int(min(ys)))
    bottom_right = (int(max(xs)), int(max(ys)))
    cv2.rectangle(image, top_left, bottom_right, (0, 0, 0), thickness=-1)


def _full_text(results) -> str:
    return "\n".join(text for _, text, _ in results if text)


def _mask_index(image, results, index: int, redacted_texts: List[str], masked_indices: Set[int]) -> None:
    if index in masked_indices or index >= len(results):
        return

    bbox, text, _ = results[index]
    mask_text(image, bbox)
    redacted_texts.append(text)
    masked_indices.add(index)


def _y_center(bbox) -> float:
    return sum(point[1] for point in bbox) / len(bbox)


def _height(bbox) -> float:
    ys = [point[1] for point in bbox]
    return max(ys) - min(ys)


def _same_line(results, first_index: int, second_index: int) -> bool:
    first_bbox = results[first_index][0]
    second_bbox = results[second_index][0]
    tolerance = max(_height(first_bbox), _height(second_bbox), 12) * 0.75
    return abs(_y_center(first_bbox) - _y_center(second_bbox)) <= tolerance


def _redact_direct_matches(image, results, categories: Set[str], redacted_texts: List[str], masked_indices: Set[int]) -> None:
    direct_categories = categories - {"Name", "Father's Name", "Address"}
    for index, (_, text, _) in enumerate(results):
        for category in direct_categories:
            if contains_category(category, text):
                _mask_index(image, results, index, redacted_texts, masked_indices)
                break


def _is_valid_dob_digits(digits: str) -> bool:
    return is_valid_dob_digits(digits)


def _date_token_digits(text: str) -> str:
    text = text or ""
    if re.search(r"[^0-9OoIl|SsBb\s\-/\\.]", text):
        return ""
    return ocr_digits_only(text)


def _redact_split_dates(image, results, categories: Set[str], redacted_texts: List[str], masked_indices: Set[int]) -> None:
    if "Date of Birth" not in categories:
        return

    for start_index in range(len(results)):
        digits = ""
        indices = []

        for index in range(start_index, min(start_index + 12, len(results))):
            text = results[index][1] or ""
            token_digits = _date_token_digits(text)

            if indices and not _same_line(results, indices[0], index):
                break

            if not token_digits:
                if indices and re.fullmatch(r"[\s\-/\\.]+", text):
                    indices.append(index)
                    continue
                if indices:
                    break
                continue

            digits += token_digits
            indices.append(index)

            if len(digits) == 8 and _is_valid_dob_digits(digits):
                for matched_index in indices:
                    _mask_index(image, results, matched_index, redacted_texts, masked_indices)
                break

            if len(digits) > 8:
                break


def _mask_date_sequence_from(
    image,
    results,
    start_index: int,
    redacted_texts: List[str],
    masked_indices: Set[int],
) -> bool:
    digits = ""
    indices = []

    for index in range(start_index, min(start_index + 12, len(results))):
        text = results[index][1] or ""

        if contains_dob(text):
            _mask_index(image, results, index, redacted_texts, masked_indices)
            return True

        token_digits = _date_token_digits(text)
        if not token_digits:
            if indices and re.fullmatch(r"[\s\-/\\.]+", text):
                indices.append(index)
                continue
            if indices:
                break
            continue

        if indices and not _same_line(results, indices[0], index):
            break

        digits += token_digits
        indices.append(index)

        if len(digits) == 8 and _is_valid_dob_digits(digits):
            for matched_index in indices:
                _mask_index(image, results, matched_index, redacted_texts, masked_indices)
            return True

        if len(digits) > 8:
            break

    return False


def _redact_labelled_dates(image, results, categories: Set[str], redacted_texts: List[str], masked_indices: Set[int]) -> None:
    if "Date of Birth" not in categories:
        return

    for index, (_, text, _) in enumerate(results):
        if not DATE_LABEL_PATTERN.search(text or ""):
            continue

        if contains_dob(text):
            _mask_index(image, results, index, redacted_texts, masked_indices)
            continue

        if DATE_LABEL_ONLY_PATTERN.search(text or "") or "birth" in (text or "").lower():
            _mask_date_sequence_from(image, results, index + 1, redacted_texts, masked_indices)


def _next_numeric_token_on_same_line(results, first_index: int, index: int) -> str:
    if index + 1 >= len(results):
        return ""
    if not _same_line(results, first_index, index + 1):
        return ""

    next_text = results[index + 1][1]
    if re.search(r"[A-Za-z]", next_text or ""):
        return ""
    return digits_only(next_text)


def _previous_numeric_token_on_same_line(results, first_index: int) -> str:
    if first_index <= 0:
        return ""
    if not _same_line(results, first_index, first_index - 1):
        return ""

    previous_text = results[first_index - 1][1]
    if re.search(r"[A-Za-z]", previous_text or ""):
        return ""
    return digits_only(previous_text)


def _redact_split_numeric_ids(image, results, categories: Set[str], redacted_texts: List[str], masked_indices: Set[int]) -> None:
    if not ({"Aadhaar Number", "VID Number"} & categories):
        return

    for start_index in range(len(results)):
        digits = ""
        indices = []

        for index in range(start_index, min(start_index + 16, len(results))):
            text = results[index][1] or ""
            token_digits = digits_only(text)
            if not token_digits:
                if indices:
                    break
                continue

            if indices and not _same_line(results, indices[0], index):
                break

            if re.search(r"[A-Za-z]", text) and indices:
                break

            digits += token_digits
            indices.append(index)

            if len(digits) == 12 and digits[0] in "23456789" and "Aadhaar Number" in categories:
                previous_digits = _previous_numeric_token_on_same_line(results, indices[0])
                if previous_digits and len(previous_digits) + len(digits) <= 16:
                    break

                next_digits = _next_numeric_token_on_same_line(results, indices[0], index)
                if next_digits and len(digits) + len(next_digits) <= 16:
                    continue
                for matched_index in indices:
                    _mask_index(image, results, matched_index, redacted_texts, masked_indices)
                break

            if len(digits) == 16 and "VID Number" in categories:
                for matched_index in indices:
                    _mask_index(image, results, matched_index, redacted_texts, masked_indices)
                break

            if len(digits) > 16:
                break


def _redact_address_sequence(image, results, categories: Set[str], redacted_texts: List[str], masked_indices: Set[int]) -> None:
    if "Address" not in categories:
        return

    start_redacting = False
    for index, (_, text, _) in enumerate(results):
        if contains_category("Address", text):
            _mask_index(image, results, index, redacted_texts, masked_indices)
            continue

        if re.search(r"\b(?:address|addr|add|enrolment|enrollment|c/o|s/o|d/o|w/o)\b", text, re.IGNORECASE):
            start_redacting = True
            _mask_index(image, results, index, redacted_texts, masked_indices)
            continue

        if start_redacting:
            _mask_index(image, results, index, redacted_texts, masked_indices)
            if re.search(r"\b[1-9]\d{5}\b", text):
                start_redacting = False


def _mask_next_name_candidate(image, results, index: int, redacted_texts: List[str], masked_indices: Set[int]) -> None:
    for start_index in range(index + 1, min(index + 5, len(results))):
        candidate_parts = []
        candidate_indices = []

        for next_index in range(start_index, min(start_index + 5, len(results))):
            next_text = (results[next_index][1] or "").strip()
            if not next_text or re.search(r"\d", next_text):
                break
            if candidate_indices and not _same_line(results, candidate_indices[0], next_index):
                break

            candidate_parts.append(next_text)
            candidate_indices.append(next_index)

            if is_name_candidate(" ".join(candidate_parts)):
                for candidate_index in candidate_indices:
                    _mask_index(image, results, candidate_index, redacted_texts, masked_indices)
                return


def _redact_name_line_groups(
    image,
    results,
    redacted_texts: List[str],
    masked_indices: Set[int],
) -> None:
    index = 0
    while index < len(results):
        group_indices = [index]
        next_index = index + 1

        while next_index < len(results) and _same_line(results, group_indices[0], next_index):
            group_indices.append(next_index)
            next_index += 1

        candidate_parts = []
        candidate_indices = []
        for group_index in group_indices:
            text = (results[group_index][1] or "").strip()
            if not text or re.search(r"\d", text) or contains_dob(text):
                if is_name_candidate(" ".join(candidate_parts)):
                    for candidate_index in candidate_indices:
                        _mask_index(image, results, candidate_index, redacted_texts, masked_indices)
                candidate_parts = []
                candidate_indices = []
                continue

            candidate_parts.append(text)
            candidate_indices.append(group_index)

        if is_name_candidate(" ".join(candidate_parts)):
            for candidate_index in candidate_indices:
                _mask_index(image, results, candidate_index, redacted_texts, masked_indices)

        index = next_index


def _redact_labelled_names(image, results, categories: Set[str], redacted_texts: List[str], masked_indices: Set[int]) -> None:
    for index, (_, text, _) in enumerate(results):
        if "Name" in categories:
            if NAME_LABEL_PATTERN.search(text):
                _mask_index(image, results, index, redacted_texts, masked_indices)
            elif NAME_LABEL_ONLY_PATTERN.search(text):
                _mask_next_name_candidate(image, results, index, redacted_texts, masked_indices)

        if "Father's Name" in categories:
            if FATHER_NAME_PATTERN.search(text):
                _mask_index(image, results, index, redacted_texts, masked_indices)
            elif FATHER_LABEL_ONLY_PATTERN.search(text):
                _mask_next_name_candidate(image, results, index, redacted_texts, masked_indices)


def _redact_contextual_names(
    image,
    results,
    doc_type: str,
    categories: Set[str],
    redacted_texts: List[str],
    masked_indices: Set[int],
) -> None:
    if not ({"Name", "Father's Name"} & categories):
        return

    text = _full_text(results)
    if not has_identity_context(doc_type, text):
        return

    for index, (_, result_text, _) in enumerate(results):
        if is_name_candidate(result_text):
            _mask_index(image, results, index, redacted_texts, masked_indices)

    _redact_name_line_groups(image, results, redacted_texts, masked_indices)


def _apply_categories(image, results, doc_type: str, categories: Iterable[str]):
    redacted_texts: List[str] = []
    masked_indices: Set[int] = set()
    category_set = expand_categories_for_document(categories, doc_type)

    _redact_direct_matches(image, results, category_set, redacted_texts, masked_indices)
    _redact_split_dates(image, results, category_set, redacted_texts, masked_indices)
    _redact_labelled_dates(image, results, category_set, redacted_texts, masked_indices)
    _redact_split_numeric_ids(image, results, category_set, redacted_texts, masked_indices)
    _redact_address_sequence(image, results, category_set, redacted_texts, masked_indices)
    _redact_labelled_names(image, results, category_set, redacted_texts, masked_indices)
    _redact_contextual_names(image, results, doc_type, category_set, redacted_texts, masked_indices)

    return image, redacted_texts


def _redact_categories(image, results, doc_type: str, categories: Iterable[str]):
    image, redacted_texts = _apply_categories(image, results, doc_type, categories)

    print("\nRedacted Texts:")
    for redacted in redacted_texts:
        print(redacted)

    return image


def redact_common_patterns(image, results, patterns):
    redacted_categories = {"Address", "Phone Number", "Date of Birth", "Name", "Father's Name"}
    return _apply_categories(image, results, "", redacted_categories)


def redact_specific_patterns(image, results, patterns):
    redacted_texts = []
    masked_indices: Set[int] = set()

    for index, (_, text, _) in enumerate(results):
        for pattern_value in patterns.values():
            if pattern_value and re.search(pattern_value, text, re.IGNORECASE):
                _mask_index(image, results, index, redacted_texts, masked_indices)
                break

    return image, redacted_texts


def redact(image, results, doc_type):
    return _redact_categories(image, results, doc_type, ALL_PII_CATEGORIES)


def redact_specific_pii(image, results, doc_type, pii_to_redact_list):
    return _redact_categories(image, results, doc_type, pii_to_redact_list)
