FROM --platform=linux/amd64 amd64/python:3.12-alpine

WORKDIR /app

COPY . .
RUN echo "Updating repos..." && apk update > /dev/null && \
    adduser -D appuser

USER appuser
ENV PATH="/home/appuser/.local/bin:$PATH"

RUN echo "Upgrading pip..." && python3 -m pip install --upgrade pip && \
    echo "Installing pip packages from requirements.txt..." && pip install -r requirements.txt

CMD ["python3", "app.py"]