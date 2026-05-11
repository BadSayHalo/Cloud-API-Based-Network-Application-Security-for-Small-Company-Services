FROM node:20-alpine
RUN npm install -g npm@latest
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 4001
CMD ["npm", "start"]