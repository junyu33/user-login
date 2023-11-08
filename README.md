## 部署文档

> 也可以访问 project.junyu33.me 访问在线 demo.

解压项目源码，运行以下指令：

```sh
sudo apt install mysql
pip install -r requirements.txt
```

登录mysql导入数据库：

```sh
mysql -u root -p
source init.sql
```

在项目根目录中创建`.env`文件，并填入以下内容：

```sh
MAIL_USERNAME=
MAIL_PASSWORD=
DB_PASSWORD=
RECAPTCHA_SITE_KEY=
RECAPTCHA_SECRET_KEY=
AES_KEY=
JWT_KEY_BASE64=
NONCE_EXPIRE_TIME=
```

启动项目：

```sh
python3 server.py
```

