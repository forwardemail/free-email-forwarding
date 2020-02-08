FROM node:lts-alpine

RUN \
  apk update && \
  apk add --no-cache \
    python3 \
    && \
  cp /usr/bin/python3 /usr/bin/python && \
  pip3 install \
    pyspf \
    dnspython \
    dkimpy

WORKDIR /app

COPY package*.json ./
COPY yarn.lock yarn.lock

RUN npm i -g pm2 && npx yarn --prod

COPY index.js index.js
COPY app.js app.js
COPY helpers/* ./helpers/
COPY .env.* ./
COPY ecosystem.json ecosystem.json

ENV NODE_ENV production

EXPOSE 25
EXPOSE 465
EXPOSE 587

CMD ["npm", "run", "start"]
