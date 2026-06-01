FROM python:3.11-alpine@sha256:db8703afcff4954c737f8c81b02dcfa0e3e93815a3029eb9e31d81a5ad9c4ece

WORKDIR /app

COPY requirements.txt requirements.lock ./
RUN python3 -m pip install --no-cache-dir --require-hashes -r requirements.lock

COPY . .

CMD ["python3", "app.py"]
