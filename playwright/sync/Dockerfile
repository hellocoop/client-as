# mock sync server
FROM node:20-alpine
WORKDIR /usr/src/app
COPY . .
RUN npm install
EXPOSE 8888
CMD ["node", "sync.js"]