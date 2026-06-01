FROM python:3.12-alpine@sha256:2d07747661646f3d904e995a232fb19e461afde69e67e6f7f3b52c7b968a88b3

WORKDIR /app

COPY . .
RUN adduser -D appuser

USER appuser
ENV PATH="/home/appuser/.local/bin:$PATH"

RUN python3 -m pip install --user --no-cache-dir --require-hashes -r requirements.lock

CMD ["python3", "app.py"]
