# AEGIS — optional container build. SQLite only, no external services.
# Mirrors the local path: python scripts/demo.py builds the corpus + pipeline
# state and serves the console on :8000.
FROM python:3.12-slim

WORKDIR /app

COPY src/requirements.txt src/requirements.txt
RUN pip install --no-cache-dir -r src/requirements.txt

COPY . .

EXPOSE 8000
CMD ["python", "scripts/demo.py", "--port", "8000"]
