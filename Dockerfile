FROM php:8.3-apache
RUN docker-php-ext-install pdo_mysql && a2dismod mpm_event mpm_worker || true
RUN a2enmod mpm_prefork rewrite headers
COPY public/ /var/www/html/
COPY database/ /var/www/database/
EXPOSE 80
CMD ["apache2-foreground"]
