FROM python:3.6-alpine

MAINTAINER Rene Dohmen "acidjunk@gmail.com"

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app
ADD requirements /usr/src/app/requirements

RUN apk add --no-cache --virtual .build-deps gcc musl-dev openssh-client git
RUN apk add --no-cache --virtual .runtime-deps postgresql-dev

RUN pip3 install --no-cache-dir --upgrade -r requirements/base.txt && apk del .build-deps

COPY . /usr/src/app

WORKDIR /usr/src/app/server

EXPOSE 5000
CMD 'python3 app.py runserver'
