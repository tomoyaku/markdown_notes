# setup trojan server

## 安装 nginx，创建nginx用户和组

因为默认的nginx包没有ssl_preread功能，所以我们需要自己编译它

1. prepare & download source & compile

yum install dnf -y
dnf groupinstall 'Development Tools' -y
dnf install epel-release -y
dnf install wget -y
mkdir -p /tmp/nginxinstallation
cd /tmp/nginxinstallation/
wget https://nginx.org/download/nginx-1.19.1.tar.gz && tar zxvf nginx-*
wget --no-check-certificate https://jaist.dl.sourceforge.net/project/pcre/pcre/8.44/pcre-8.44.tar.gz && tar zxvf pcre-*
wget --no-check-certificate https://www.zlib.net/zlib-1.2.12.tar.gz && tar zxvf zlib-*
wget --no-check-certificate https://www.openssl.org/source/openssl-1.1.1g.tar.gz && tar zxvf openssl-*
sudo dnf install perl perl-devel perl-ExtUtils-Embed libxslt libxslt-devel libxml2 libxml2-devel gd gd-devel GeoIP GeoIP-devel gperftools-devel -y

2. 添加用户

sudo useradd --system --home /var/cache/nginx --shell /sbin/nologin --comment "nginx user" --user-group nginx
3. 准备编译
cd nginx-1.19.1

sudo ./configure \
--prefix=/etc/nginx \
--sbin-path=/usr/sbin/nginx \
--pid-path=/var/run/nginx.pid \
--lock-path=/var/run/nginx.lock \
--conf-path=/etc/nginx/nginx.conf \
--modules-path=/etc/nginx/modules \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--user=nginx \
--group=nginx \
--with-pcre=../pcre-8.44 \
--with-pcre-jit \
--with-zlib=../zlib-1.2.12 \
--with-openssl=../openssl-1.1.1g \
--with-http_ssl_module \
--with-http_v2_module \
--with-threads \
--with-file-aio \
--with-http_degradation_module \
--with-http_auth_request_module \
--with-http_geoip_module \
--with-http_realip_module \
--with-http_secure_link_module \
--with-cpp_test_module \
--with-debug \
--with-google_perftools_module \
--with-mail \
--with-mail_ssl_module \
--with-http_mp4_module \
--with-http_flv_module \
--with-stream \
--with-stream_ssl_module \
--with-stream_ssl_preread_module \
--with-http_dav_module \
--with-http_image_filter_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_addition_module \
--with-http_random_index_module \
--with-http_slice_module \
--with-http_sub_module \
--with-http_xslt_module \
--with-select_module \
--with-poll_module

make 
make install

sudo ln -s /usr/lib64/nginx/modules /etc/nginx/modules
sudo nginx -t
sudo mkdir -p /var/cache/nginx && sudo nginx -t
sudo vim /usr/lib/systemd/system/nginx.service
写入
```
[Unit]
Description=nginx - high performance web server
Documentation=https://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -c /etc/nginx/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```
systemctl daemon-reload
sudo systemctl start nginx.service && sudo systemctl enable nginx.service
sudo systemctl is-enabled nginx.service
sudo systemctl status nginx.service

mkdir ~/.vim/
cp -r /tmp/nginxinstallation/nginx-1.19.1/contrib/vim/* ~/.vim/

## 测试
现在在浏览器里打开应该能看到（没有防火墙的情况下）
http://www.domin.com/
记住用http，而且要加www
如果开了防火墙试试以下几行
firewall-cmd --zone=public --permanent --add-service=http
firewall-cmd --zone=public --permanent --add-service=https
firewall-cmd --reload

## 补充

具体可参考这个链接，如果还可以用的话


## 处理证书
mkdir -p /etc/nginx/ssl
openssl genrsa 4096 > account.key
openssl genrsa 4096 > domain.key
openssl req -new -sha256 -key domain.key -out domain.csr

打开ngnix配置文件
vim /etc/nginx/nginx.conf
找合适的地方加一项
```
    server {
        server_name www.domin.com domin.com;
        location ^~ /.well-known/acme-challenge/ {
            alias /home/acme_challenge/;
            try_files $uri =404;
        }
        location / {
            rewrite ^/(.*)$ https://domin.com/$1 permanent;
        }
    }
```

nginx -t
确认配置没问题
service nginx restart

注意上边这个路径一定不要放在特殊目录里，因为权限问题所以放一个每个用户都能访问到的目录
mkdir -p /home/acme_challenge
pip install acme-tiny
acme-tiny --account-key ./account.key --csr ./domain.csr --acme-dir /home/acme_challenge/ > ./signed.crt

会显示
```
Parsing account key...
Parsing CSR...
Found domains: domin.com
Getting directory...
Directory found!
Registering account...
Already registered! Account ID: https://acme-v02.api.letsencrypt.org/acme/acct/771298756
Creating new order...
Order created!
Verifying domin.com...
domin.com verified!
Signing certificate...
Certificate signed!
```
就表示成功了！

成功之后再执行：

wget -O - https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem > intermediate.pem
cat signed.crt intermediate.pem > chained.pem


### 如果用阿里云送免费的
参考这里

https://zhuanlan.zhihu.com/p/498463103

## 配置trojan

随便从网上找一个trojan的一键安装就可以

使用
```
service trojan start 可以启动
service trojan status 可以获取期执行状态
```

有一个需要注意一点，我们一般分配一个子级域名比如
`trojan.domin.com`
`great.domin.com`
其中`trojan`,`great`一定要在域名的解析里添加上，不然 nginx 即使做分流也是无效的!

## 配置 sock5

wget –no-check-certificate https://raw.github.com/Lozy/danted/master/install.sh -O install.sh
bash install.sh --port=端口 --user=用户名 --passwd=密码

## 安装 PHP mysql

```
# 添加源，因为默认的centos源没有php74
yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
yum -y install https://rpms.remirepo.net/enterprise/remi-release-7.rpm
sudo yum -y install yum-utils
sudo yum-config-manager --enable remi-php74
sudo yum update
sudo yum install php php-cli
sudo yum install -y php php-cli php-fpm php-mysqlnd php-zip php-devel php-gd php-mcrypt php-mbstring php-curl php-xml php-pear php-bcmath php-json
```
vi /etc/php.ini
cgi.fix_pathinfo=0
```

vi /etc/php-fpm.d/www.conf

改五处
listen = /var/run/php-fpm/php-fpm.sock
listen.owner = nginx
listen.group = nginx
listen.mode = 0660
user = nginx
group = nginx
退出
sudo systemctl start php-fpm
sudo systemctl enable php-fpm

cp -p /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak

## 下载安装wordpress

cd /home
wget https://wordpress.org/latest.tar.gz
tar zxvf latest.tar.gz
chown -R nginx:nginx /home/wordpress

## SS5

wget --no-check-certificate https://raw.github.com/Lozy/danted/master/install.sh -O install.sh 
bash install.sh --port=2022 --user=sockd --passwd=sockd