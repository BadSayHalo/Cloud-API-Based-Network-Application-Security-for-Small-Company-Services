FROM nginx:alpine

# Copy file cấu hình Nginx vào container
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy toàn bộ file HTML/JS vào thư mục web
COPY . /usr/share/nginx/html/

EXPOSE 80