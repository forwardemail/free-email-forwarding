FROM node:10-stretch

WORKDIR /app

RUN \
  apt-get -y update && \
  apt-get -y upgrade && \
  apt-get install -y software-properties-common redis-server spamassassin spamc python openssl python-pip curl && \
  pip install pyspf pydns ipaddr dkimpy pynacl authres dnspython pydns

RUN \
  openssl genrsa -out dkim-private.key 1024 && \
  openssl rsa -in dkim-private.key -pubout -out dkim-public.key && \
  echo "Add this to your DNS zonefile:" && \
  sed '3,3!d' dkim-public.key | sed ':a;N;$!ba;s/\n//g' | xargs -I{} echo "default._domainkey 14400 IN TXT \"v=DKIM1; k=rsa; p={}\"" | tee DKIM-TXT-record

COPY package.json yarn.lock /app/
RUN yarn

COPY * /app/

EXPOSE 25

ENV IP_ADDRESS ""
ENV EXCHANGES ""
ENV DKIM_PRIVATE_KEY /app/dkim-private.key

CMD \
  /usr/sbin/spamd -d --pidfile=/var/run/spamd.pid && \
  /usr/bin/redis-server /etc/redis/redis.conf && \
  /app/index.js

#docker run -e --network host --hostname <yourdomain.com> --name <container name> -d forward-email:latest

# Add the following line to your DNS zonefile:
#docker exec <container name> cat /app/DKIM-TXT-record
