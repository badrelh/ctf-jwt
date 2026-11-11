FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates ./templates
COPY static ./static

RUN mkdir -p /app/images

EXPOSE 5004
CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT:-5004} --workers 2 --threads 4 app:app"]
