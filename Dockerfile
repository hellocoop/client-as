# AS for Mobile
FROM node:20-alpine
WORKDIR /usr/src/app
COPY ./dist ./dist
COPY ./keys ./keys
COPY ./package*.json ./
RUN npm i --only=production
# default client port
EXPOSE 3000
ENV IP=0.0.0.0
CMD ["npm","run", "start"]
