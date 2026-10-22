FROM python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d

WORKDIR /app

COPY . .
RUN adduser -D appuser

USER appuser
ENV PATH="/home/appuser/.local/bin:$PATH"

RUN python3 -m pip install --user --no-cache-dir --require-hashes -r requirements.lock

CMD ["python3", "app.py"]
