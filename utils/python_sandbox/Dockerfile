FROM python:3.12-slim

ADD requirements.txt requirements.txt
RUN pip install -r requirements.txt
RUN apt-get update && apt-get -y install ripgrep global git && apt-get clean
