FROM python:3.12-slim
COPY mitm_strip_versions.py /app/mitm.py
# proxy listens on 4434, forwards to server:443 (override TARGET via edit if needed)
CMD ["python3","-I","/app/mitm.py"]
