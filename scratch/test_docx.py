import sys
sys.path.append("d:/SAKETH/Hackathons/AI_Frontier")
from file_scanner.file_scanner import redact_file

with open("test.docx", "rb") as f:
    file_bytes = f.read()

res = redact_file(file_bytes, "test.docx", [{"item": "Saketh", "type": "NAME"}])
print(res.get('success', False))
print(res.get('error', 'No Error'))
