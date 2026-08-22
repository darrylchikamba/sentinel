FROM python:3.12-slim

WORKDIR /app

COPY server/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home sentinel_user

COPY --chown=sentinel_user:sentinel_user server/ /app

USER sentinel_user

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]