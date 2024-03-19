# AS for Mobile
FROM node:20-alpine
WORKDIR /usr/src/app
COPY ./dist ./
COPY ./package*.json ./
RUN npm i --only=production
# default client port
EXPOSE 3000
ENV IP=0.0.0.0
CMD ["node", "index.js"]
