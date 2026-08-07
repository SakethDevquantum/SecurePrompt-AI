import sys
sys.path.append("d:/SAKETH/Hackathons/AI_Frontier")
from file_scanner.file_scanner import redact_file

with open("idealogy.jpg", "rb") as f:
    file_bytes = f.read()

res = redact_file(file_bytes, "idealogy.jpg", [{"item": "saketh", "type": "NAME"}])
print(res)
