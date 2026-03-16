FROM node:22

WORKDIR /app

COPY package*.json ./
# Install all dependencies including devDependencies (needed for tsx/typescript)
RUN npm install

COPY . .

# App Runner usually expects 8080, but if you stay on 3000, 
# ensure the App Runner Service Port configuration matches this.
EXPOSE 3000

CMD ["npm", "start"]
