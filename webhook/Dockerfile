FROM alpine

RUN apk add --no-cache py3-flask
COPY ./webhook.py /

ENV FLASK_APP=webhook
CMD ["flask", "run", "--host", "0.0.0.0"]
