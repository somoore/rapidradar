FROM python:3.11-alpine@sha256:5fb4bc53dd0180955e31e5245b648bbb24a4ac4ab03a1de81513642325220bcd

WORKDIR /app

COPY requirements.txt requirements.lock ./
RUN python3 -m pip install --no-cache-dir --require-hashes -r requirements.lock

COPY . .

CMD ["python3", "app.py"]
