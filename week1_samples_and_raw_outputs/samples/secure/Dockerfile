FROM python:3.12.4-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -r -u 1001 appuser
USER appuser
HEALTHCHECK --interval=30s CMD python -c "print('ok')" || exit 1
CMD ["python", "main.py"]
