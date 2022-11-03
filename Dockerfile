FROM python:3.10.7-alpine

WORKDIR /app

ADD . /app

RUN apk add build-base linux-headers pcre-dev tzdata

RUN apk add --no-cache mariadb-dev build-base mariadb-connector-c-dev

RUN command pip install uwsgi

RUN pip3 install -r requirements.txt

RUN apk del mariadb-dev build-base

RUN ln -sf /usr/share/zoneinfo/Asia/Singapore /etc/localtime

# Run the command to start uWSGI
CMD ["uwsgi", "app.ini"]