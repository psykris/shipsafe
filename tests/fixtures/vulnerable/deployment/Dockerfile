FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# VULNERABLE: no USER directive — container runs as root
EXPOSE 8000
CMD ["python", "app.py"]
