FROM python:3.11-slim
RUN mkdir /app
WORKDIR /app
ADD requirements.txt /app
RUN pip3 install -r requirements.txt
ADD . /app
EXPOSE 5000
ENTRYPOINT ["sh", "entrypoint.sh"]