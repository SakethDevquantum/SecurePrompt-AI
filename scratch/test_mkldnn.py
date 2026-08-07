from paddleocr import PaddleOCR
try:
    ocr = PaddleOCR(use_angle_cls=True, lang="en", enable_mkldnn=False)
    print("enable_mkldnn=False succeeded")
except Exception as e:
    print("enable_mkldnn error:", e)

try:
    ocr = PaddleOCR(use_angle_cls=True, lang="en", use_mkldnn=False)
    print("use_mkldnn=False succeeded")
except Exception as e:
    print("use_mkldnn error:", e)
