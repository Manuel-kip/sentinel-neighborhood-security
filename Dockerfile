FROM php:8.3-apache
RUN docker-php-ext-install pdo_mysql mbstring
COPY public/ /var/www/html/
COPY database/ /var/www/database/
RUN a2enmod rewrite headers
EXPOSE 80
