from docx import Document

from app.utils.pii_redaction import ALL_PII_CATEGORIES, redact_text


def _iter_paragraphs(container):
    for paragraph in container.paragraphs:
        yield paragraph

    for table in getattr(container, "tables", []):
        for row in table.rows:
            for cell in row.cells:
                yield from _iter_paragraphs(cell)


def _replace_paragraph_text(paragraph, text: str) -> None:
    if paragraph.runs:
        paragraph.runs[0].text = text
        for run in paragraph.runs[1:]:
            run.text = ""
    else:
        paragraph.add_run(text)


def redact_docx_content(doc: Document, document_type: str) -> tuple:
    redacted_texts = []

    for paragraph in _iter_paragraphs(doc):
        original_text = paragraph.text
        if not original_text.strip():
            continue

        new_text = redact_text(original_text, ALL_PII_CATEGORIES, document_type)
        if original_text != new_text:
            _replace_paragraph_text(paragraph, new_text)
            redacted_texts.append(original_text)

    return doc, redacted_texts


def redact_specific_pii(text: str, pii_to_redact_list: list, document_type: str) -> str:
    return redact_text(text, pii_to_redact_list, document_type)


def process_docx_file(doc: Document, document_type: str, pii_to_redact_list: list) -> tuple:
    redacted_texts = []

    for paragraph in _iter_paragraphs(doc):
        original_text = paragraph.text
        if not original_text.strip():
            continue

        new_text = redact_specific_pii(original_text, pii_to_redact_list, document_type)
        if original_text != new_text:
            _replace_paragraph_text(paragraph, new_text)
            redacted_texts.append(original_text)

    return doc, redacted_texts
