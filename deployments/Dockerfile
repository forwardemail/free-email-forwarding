# Use Ubuntu latest LTS
FROM ubuntu:latest

WORKDIR /

RUN \
  apt-get -y update && \
  apt-get -y upgrade && \
  apt-get -y install software-properties-common && \
  add-apt-repository -y ppa:chris-lea/redis-server && \
  apt-get update && \
  apt-get install -y npm redis-server spamassassin spamc python authbind openssl python-pip curl && \
  /usr/sbin/spamd -d --pidfile=/var/run/spamd.pid && \
  /usr/bin/redis-server /etc/redis/redis.conf && \
  touch /etc/authbind/byport/25 && \
  chmod 755 /etc/authbind/byport/25 && \
  touch /etc/authbind/byport/465 && \
  chmod 755 /etc/authbind/byport/465 && \
  touch /etc/authbind/byport/\!587 && \
  openssl genrsa -out private.key 1024 && \
  openssl rsa -in private.key -pubout -out public.key && \
  sed '2,3!d' public.key | sed ':a;N;$!ba;s/\n//g' | xargs -I{} echo "default._domainkey 14400 IN TXT \"v=DKIM1; k=rsa; p={}\"" > DKIM-TXT-record && \
  pip install pyspf pydns ipaddr dkimpy pynacl authres dnspython pydns && \
  npm install python-spfcheck2 python-dkim-verify forward-email auto-bind is-ci && \
  sed -i "s/  \.stderr\.split(' ')\[1\]/  \.stdout\.split(' ')\[1\]/" node_modules/python-spfcheck2/index.js && \
  curl "https://raw.githubusercontent.com/niftylettuce/python-dkim-verify/c5db6545a6640ac70e0f396c61f38da378b7c764/index.js" > node_modules/python-dkim-verify/index.js && \
  curl "https://raw.githubusercontent.com/niftylettuce/python-spfcheck2/6494dfa0abb9b062828dcec78bf9c412e44d84c6/index.js" > node_modules/python-spfcheck2/index.js && \
  curl "https://raw.githubusercontent.com/niftylettuce/forward-email/b9f6cb8cfaef8024fa51b4a023ff4f3812993d05/README.md" > forward-email.js && \
  sed -i '337,401!d' forward-email.js; exit 0 /*

RUN nohup /usr/bin/redis-server /etc/redis/redis.conf

EXPOSE 25

CMD /usr/bin/redis-server /etc/redis/redis.conf && nodejs forward-email.js

#docker exec <container name> cat /DKIM-TXT-record