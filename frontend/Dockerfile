FROM nginx:alpine

# Xóa cấu hình mặc định của Nginx
RUN rm /etc/nginx/conf.d/default.conf

# Copy file cấu hình Nginx mới của bạn vào
COPY nginx.conf /etc/nginx/conf.d/default.conf

# LƯU Ý: Copy TẤT CẢ các file .html vào thư mục của Nginx
# (Dấu * sẽ gom cả index.html, login.html, admin.html)
COPY *.html /usr/share/nginx/html/

# Nếu bạn có thêm thư mục css, js, images thì dùng lệnh này thay thế:
# COPY . /usr/share/nginx/html/

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]