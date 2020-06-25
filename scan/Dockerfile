FROM python:3-alpine

RUN mkdir /usr/src/app

WORKDIR /usr/src/app

COPY ./sast.py /usr/src/app

COPY ./requirements.txt /usr/src/app

RUN pip install --no-cache-dir -r requirements.txt

CMD python3 ./sast.py