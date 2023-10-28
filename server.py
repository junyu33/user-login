#导入数据库模块
import pymysql
#导入Flask框架，这个框架可以快捷地实现了一个WSGI应用 
from flask import Flask
#默认情况下，flask在程序文件夹中的templates子文件夹中寻找模块
from flask import render_template
#导入前台请求的模块
from flask import request
#导入json模块
from flask import jsonify
# password hashing library
import bcrypt
import traceback  
#传递根目录
app = Flask(__name__)

def regist_sql(cursor, sql, db):
    try:
        # 执行sql语句
        cursor.execute(sql)
        # 提交到数据库执行
        db.commit()
        return 0  # success 
    except:
        #抛出错误信息
        traceback.print_exc()
        # 如果发生错误则回滚
        db.rollback()
        return -1 # unexpected error

def login_sql(cursor, sql, db):
    try:
        # 执行sql语句
        cursor.execute(sql)
        results = cursor.fetchall()
        if len(results)==1:
            return 0 # success
        else:
            return 1 # invalid password
    except:
        # 如果发生错误则回滚
        traceback.print_exc()
        db.rollback()

    # 关闭数据库连接
    db.close()
    return -1 #unexpected error


#默认路径访问登录页面
@app.route('/')
def login():
    return render_template('login.html')
 
#默认路径访问注册页面
@app.route('/regist')
def regist():
    return render_template('regist.html')

#获取注册请求及处理
@app.route('/registuser', methods=['POST'])
def getRigist():
#把用户名和密码注册到数据库中
 
    #连接数据库,此前在数据库中创建数据库TESTDB
    db = pymysql.connect(host="localhost", user="root", password="123456", database="PROJECT")
    # 使用cursor()方法获取操作游标 
    cursor = db.cursor()
    data = request.get_json()
    user = data['user']
    hashed_password = data['hashedPassword']
    print(hashed_password)

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(hashed_password.encode('utf-8'), salt)

    # insert username, salt keypair
    sql = "INSERT INTO user_salt(username, salt) VALUES ('%s', '%s')" % (user, salt.decode('utf-8'))
    print(sql)
    if regist_sql(cursor, sql, db) == -1:
        return "fail"
    else:
        print("insert salt success")

    # SQL 插入语句
    sql = "INSERT INTO user_password(username, hashed_password) VALUES ('%s', '%s')" % (user, hashed_password.decode('utf-8'))
    print(sql)

    if regist_sql(cursor, sql, db) == 0:
        return render_template('login.html')
    else:
        return "fail"

#获取登录参数及处理
@app.route('/login', methods=['POST'])
def getLogin():
#查询用户名及密码是否匹配及存在
    #连接数据库,此前在数据库中创建数据库TESTDB
    db = pymysql.connect(host="localhost", user="root", password="123456", database="PROJECT")
    # 使用cursor()方法获取操作游标 
    cursor = db.cursor()
    data = request.get_json()
    username = data['user']
    hashed_password = data['hashedPassword']
    # retrive salt from database
    sql = "SELECT salt FROM user_salt WHERE username = '%s'" % (username)
    cursor.execute(sql)
    results = cursor.fetchall()
    if len(results) == 0:
        return "fail"
    salt = results[0][0]
    print('salt from login:', salt)

    hashed_password = bcrypt.hashpw(hashed_password.encode('utf-8'), salt.encode('utf-8'))
    hashed_password = hashed_password.decode('utf-8')
    print(hashed_password)
    # SQL 查询语句
    sql = "SELECT * FROM user_password WHERE username = '%s' AND hashed_password = '%s'" % (username, hashed_password)

    status = login_sql(cursor, sql, db)
    # 关闭数据库连接
    db.close()
    if status == 0:
        return jsonify({'message': 'Authentication successful'}), 200 
    elif status == 1:
        return jsonify({'message': 'Authentication failed. Invalid password.'}), 401
    else:
        return "unexpected error", 401
    
 
#使用__name__ == '__main__'是 Python 的惯用法，确保直接执行此脚本时才
#启动服务器，若其他程序调用该脚本可能父级程序会启动不同的服务器
if __name__ == '__main__':
    app.run(debug=True)
    

