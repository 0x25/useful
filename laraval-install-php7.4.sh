#!/bin/bash
# 30/04/2020

#PHP version
version='7.4'
#site name
siteName='blog'

echo "Update / Upgrade"
sudo add-apt-repository -y ppa:ondrej/php
sudo apt update && sudo apt upgrade -y

echo "Install PHP ${version}"
sudo apt install -y php${version} php${version}-fpm

echo "Install PHP Laravel requirements"
sudo apt install -y php${version}-cli php${version}-curl php${version}-mysqli php${version}-sqlite3 php${version}-gd php${version}-xml php${version}-mbstring php${version}-common php${version}-zip

echo "Install PHP mcrypt - laravel requirement"
sudo apt-get -y install gcc make autoconf libc-dev pkg-config
sudo apt-get -y install php${version}-dev php-pear libmcrypt-dev
sudo pecl install mcrypt-1.0.3
cmd='echo "extension=mcrypt.so" >> /etc/php/'${version}'/cli/php.ini'
sudo bash -c "$cmd" 
cmd='echo "extension=mcrypt.so" >> /etc/php/'${version}'/fpm/php.ini'
sudo bash -c "$cmd"
 
echo "Install composer"
cd /tmp
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer

echo "Install laravel composer"
composer global require laravel/installer
reset

echo "Add vendor composer to user path"
echo 'PATH="~/.config/composer/vendor/bin:$PATH"' >> ~/.bashrc

echo "Create www"
sudo mkdir /var/www
sudo chown www-data:www-data /var/www
sudo adduser $USER www-data
sudo chmod 770 /var/www

siteecho "Create laravel test site : ${siteName}"
cd /var/www
laravel new ${siteName}
cd test
php artisan server &
firefox localhost:8000

