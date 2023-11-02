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

启动项目：

```sh
python3 server.py
```

