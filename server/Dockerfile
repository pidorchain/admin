FROM node:22-alpine
WORKDIR /app
COPY server.js admin.html package.json ./
ENV PORT=3000 DB_PATH=/data/void.db
VOLUME /data
EXPOSE 3000
CMD ["node", "server.js"]
