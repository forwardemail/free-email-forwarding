FROM node:lts-alpine

ENV NODE_ENV production

RUN \
  apk add --no-cache \
    python3 \
    && \
  ln -s /usr/bin/python3 /usr/bin/python && \
  pip3 install --no-cache-dir \
    pyspf \
    dnspython \
    dkimpy

WORKDIR /app

COPY package*.json yarn.lock ./

RUN npx yarn --prod

COPY . .

EXPOSE 25 465 587

CMD ["node", "app.js"]
