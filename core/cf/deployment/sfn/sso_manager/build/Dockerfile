FROM  --platform=linux/amd64 amd64/python:3.8.16-alpine

ENV PACKAGES aws-cli
RUN echo "Updating repos..." && apk update > /dev/null && \
    echo "Installing packages: ${PACKAGES}..." && apk add --no-cache $PACKAGES > /dev/null

RUN pip install boto3 openpyxl

COPY . .

CMD [ "python3", "app.py" ]