FROM python:3.10-alpine

RUN apk --no-cache add socat

RUN apk add gcc
RUN apk add musl-dev
RUN apk add gmp-dev

RUN pip install pycryptodome

COPY server.py server.py

CMD socat -dd -v >/dev/stdout TCP-L:50000,fork,reuseaddr EXEC:"python -u server.py"

