from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from app.utils.pii_detection import detect_pii, detect_docType
from app.utils.image_processing import redact, redact_specific_pii
from PIL import Image, ImageEnhance
import numpy as np
import easyocr
import io
import cv2
import fitz

router = APIRouter()
reader = easyocr.Reader(['en'], gpu=False)


def convert_pdf_to_images(contents: bytes):
    """Render PDF pages without requiring Poppler on Windows."""
    try:
        pdf_document = fitz.open(stream=contents, filetype="pdf")
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Unable to read the PDF file.") from exc

    images = []
    zoom_matrix = fitz.Matrix(2, 2)
    try:
        for page in pdf_document:
            pixmap = page.get_pixmap(matrix=zoom_matrix, alpha=False)
            image = Image.open(io.BytesIO(pixmap.tobytes("png"))).convert("RGB")
            images.append(image)
    finally:
        pdf_document.close()

    if not images:
        raise HTTPException(status_code=400, detail="The PDF does not contain any pages.")

    return images


async def extract_text_from_images(images):
    """Extract text from a list of images using OCR."""
    text = ""
    for image in images:
        image_bytes = io.BytesIO()
        image.save(image_bytes, format='PNG')
        ocr_results = reader.readtext(image_bytes.getvalue())
        page_text = " ".join([result[1] for result in ocr_results])
        text += page_text + "\n"
    return text

@router.post("/detect")
async def detect_pii_in_pdf(file: UploadFile = File(...)):
    # Validate file type
    if file.content_type != "application/pdf":
        return JSONResponse(status_code=400, content={"error": "Invalid file format. Only PDFs are supported."})
    
    contents = await file.read()
    images = convert_pdf_to_images(contents)
    
    # Extract text for PII detection
    text = await extract_text_from_images(images)
    pii_types, document_type = detect_pii(text)
    return {"document_type": document_type, "detected_pii": pii_types}

@router.post("/redact")
async def redact_pii_in_pdf(file: UploadFile = File(...), pii_to_redact: str = Form("all")):
    # Validate file type
    if file.content_type != "application/pdf":
        return JSONResponse(status_code=400, content={"error": "Invalid file format. Only PDFs are supported."})
    
    contents = await file.read()
    images = convert_pdf_to_images(contents)
    redacted_images = []
    pii_to_redact_list = [item.strip() for item in pii_to_redact.split(",")]

    for image in images:
        # Convert PIL image to OpenCV format
        np_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        
        # OCR to detect text for redaction
        image_bytes = io.BytesIO()
        image.save(image_bytes, format='PNG')
        results = reader.readtext(image_bytes.getvalue())
        page_text = " ".join([result[1] for result in results])
        
        # Detect document type for custom redaction
        document_type = detect_docType(page_text)
        
        # Apply redaction based on specified PII types
        if pii_to_redact == 'all':
            processed_image = redact(np_image, results, document_type)
        else:
            processed_image = redact_specific_pii(np_image, results, document_type, pii_to_redact_list)
        
        # Enhance and resize processed image for quality
        pil_image = Image.fromarray(cv2.cvtColor(processed_image, cv2.COLOR_BGR2RGB))
        upscale_factor = 2
        pil_image = pil_image.resize((pil_image.width * upscale_factor, pil_image.height * upscale_factor), Image.LANCZOS)
        enhancer = ImageEnhance.Sharpness(pil_image)
        pil_image = enhancer.enhance(2.0)
        redacted_images.append(pil_image)

    # Combine redacted images into a PDF
    pdf_buffer = io.BytesIO()
    if redacted_images:
        redacted_images[0].save(pdf_buffer, format='PDF', save_all=True, append_images=redacted_images[1:])
    pdf_buffer.seek(0)
    
    # Return the redacted PDF
    return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=redacted.pdf"})
