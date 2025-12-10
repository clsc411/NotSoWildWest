FROM node:18

# Set working directory inside the container
WORKDIR /app

# Copy dependency info first for caching
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of your app
COPY . .

# Expose the port your app runs on
EXPOSE 3000

# Command to start your server
CMD ["node", "server.js"]
