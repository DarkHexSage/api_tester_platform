FROM node:18-alpine AS builder

WORKDIR /app

COPY package*.json ./
ARG PUBLIC_URL=/
RUN npm ci

COPY public ./public
COPY src ./src

RUN npm run build -- --public-url=$PUBLIC_URL


FROM nginx:alpine

COPY --from=builder /app/build /usr/share/nginx/html

COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
