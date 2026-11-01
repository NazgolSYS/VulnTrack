
FROM python:3.14-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN adduser --disabled-password --gecos "" appuser

COPY requirements.txt .

RUN pip install --no-cache-dir --index-url https://pypi.org/simple -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
