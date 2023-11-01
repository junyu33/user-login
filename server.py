#导入数据库模块
import pymysql
#导入Flask框架，这个框架可以快捷地实现了一个WSGI应用 
from flask import Flask, json, send_from_directory
#默认情况下，flask在程序文件夹中的templates子文件夹中寻找模块
from flask import render_template
#导入前台请求的模块
from flask import request
#导入json模块
from flask import jsonify
# password hashing library
import bcrypt
import traceback  
# mail server
from flask_mail import Mail, Message
import random
# config reader
from decouple import config
# captcha renew
import time
# multi-threading
import threading 
# verify recaptcha
import requests
#传递根目录
app = Flask(__name__)

app.config['MAIL_SERVER'] = 'smtp.zoho.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = config('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = config('MAIL_PASSWORD')

app.config['RECAPTCHA_SITE_KEY'] = config('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = config('RECAPTCHA_SECRET_KEY')

mail = Mail(app)


#默认路径访问登录页面
@app.route('/')
def login():
    return render_template('login.html', app=app)
 
#默认路径访问注册页面
@app.route('/regist')
def regist():
    return render_template('regist.html')

@app.route('/forget')
def forget():
    return render_template('reset.html')

def regist_sql(cursor, sql, db):
    """
    在数据库中执行给定的SQL语句并提交事务。

    Args:
        cursor: 数据库游标，用于执行SQL语句。
        sql (str): 要执行的SQL语句。
        db: 数据库连接对象，用于提交事务和回滚操作。

    Returns:
        int: 如果执行成功，则返回0；如果发生异常，则返回-1。

    Raises:
        Exception: 如果在执行SQL语句期间发生任何异常，将引发异常。

    Note:
        此函数执行以下操作：
        1. 使用给定的游标执行提供的SQL语句。
        2. 如果执行成功，将提交事务。
        3. 如果发生异常，将打印异常信息并回滚事务。
        4. 根据执行结果返回0（成功）或-1（异常）。

    Example:
        cursor = db.cursor()
        sql = "INSERT INTO users (username, password) VALUES ('john', 'secret')"
        result = regist_sql(cursor, sql, db)
        if result == 0:
            print("SQL执行成功")
        else:
            print("SQL执行失败")

    """
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
    """
    在数据库中执行给定的SQL查询语句，用于用户登录验证。

    Args:
        cursor: 数据库游标，用于执行SQL语句。
        sql (str): 要执行的SQL查询语句。
        db: 数据库连接对象，用于回滚事务和关闭连接。

    Returns:
        int: 返回0（成功）表示验证成功，返回1（密码无效）表示验证失败，返回-1（异常）表示发生意外错误。

    Raises:
        Exception: 如果在执行SQL查询期间发生任何异常，将引发异常。

    Note:
        此函数执行以下操作：
        1. 使用给定的游标执行提供的SQL查询语句。
        2. 检查查询结果，如果结果中有且只有一个匹配项，返回0（成功），否则返回1（密码无效）。
        3. 如果发生异常，将打印异常信息并回滚事务。
        4. 无论验证成功与否，都会尝试关闭数据库连接。
        5. 根据验证结果返回0（成功）、1（密码无效）或-1（异常）。

    Example:
        cursor = db.cursor()
        sql = "SELECT * FROM users WHERE username='john' AND password='secret'"
        result = login_sql(cursor, sql, db)
        if result == 0:
            print("登录成功")
        elif result == 1:
            print("无效的密码")
        else:
            print("登录失败")

    """
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

def reset_sql(cursor, sql, db):
    """
    在数据库中执行给定的SQL语句并提交事务。

    Args:
        cursor: 数据库游标，用于执行SQL语句。
        sql (str): 要执行的SQL语句。
        db: 数据库连接对象，用于提交事务和回滚操作。

    Returns:
        int: 如果执行成功，则返回0；如果发生异常，则返回-1。

    Raises:
        Exception: 如果在执行SQL语句期间发生任何异常，将引发异常。

    Note:
        此函数执行以下操作：
        1. 使用给定的游标执行提供的SQL语句。
        2. 如果执行成功，将提交事务。
        3. 如果发生异常，将打印异常信息并回滚事务。
        4. 根据执行结果返回0（成功）或-1（异常）。

    Example:
        cursor = db.cursor()
        sql = "INSERT INTO users (username, password) VALUES ('john', 'secret')"
        result = regist_sql(cursor, sql, db)
        if result == 0:
            print("SQL执行成功")
        else:
            print("SQL执行失败")

    """
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



#默认路径访问重置密码页面
@app.route('/send_verification', methods=['POST'])
def send_verification():
    """发送验证码到用户的邮箱。

    从请求中获取用户的邮箱地址，并发送一个随机的6位数验证码到该邮箱。
    
    Request JSON:
        email (str): 用户的邮箱地址。

    Returns:
        JSON: 包含消息的 JSON 对象，描述是否成功发送验证码。
    """
    email = request.json.get('email')
    if not email:
        return jsonify({"message": "Email is required"}), 400

    # 生成随机的6位数验证码
    code = str(random.randint(100000, 999999))

    msg = Message('Your Verification Code', sender=config('MAIL_USERNAME'), recipients=[email])
    msg.body = f"Your verification code is: {code}"
    mail.send(msg)

    db = pymysql.connect(host="localhost", user="root", password=config("DB_PASSWORD"), database="PROJECT")
    cursor = db.cursor()
    sql = f"INSERT INTO user_captcha (username, captcha) VALUES ('{email}', '{code}') \
        ON DUPLICATE KEY UPDATE captcha='{code}';"

    if reset_sql(cursor, sql, db) == -1:
        return jsonify({"message": "Unexpected error"}), 500
    else:
        return jsonify({"message": "Verification code sent!"}), 200


def verify_recaptcha(response):
    # Set up the reCAPTCHA verification endpoint URL and parameters
    url = 'https://www.google.com/recaptcha/api/siteverify'
    data = {
        'secret': config('RECAPTCHA_SECRET_KEY'),
        'response': response
    }

    # Send a POST request to the reCAPTCHA verification endpoint
    response = requests.post(url, data=data)

    # Parse the JSON response
    result = response.json()

    # Return the verification result
    return result

#获取注册请求及处理
@app.route('/registuser', methods=['POST'])
def getRigist():
    """
    将用户名和哈希密码注册到数据库中。

    Returns:
        str: 如果注册成功，返回登录页面的HTML；如果注册失败，返回字符串"fail"。

    Note:
        此函数执行以下操作：
        1. 连接到数据库，使用用户名和哈希密码注册。
        2. 生成一个盐（salt）并将其与哈希密码一起插入到数据库中。
        3. 如果插入操作成功，将返回登录页面的HTML。
        4. 如果插入操作失败，将返回"fail"。

    Example:
        # 使用示例
        data = request.get_json()
        user = data['user']
        hashed_password = data['hashedPassword']
        result = getRigist()
        if result == "fail":
            print("注册失败")
        else:
            print("注册成功")
    """
    #连接数据库,此前在数据库中创建数据库PROJECT
    db = pymysql.connect(host="localhost", user="root", password=config("DB_PASSWORD"), database="PROJECT")
    # 使用cursor()方法获取操作游标 
    cursor = db.cursor()
    data = request.get_json()
    user = data['user']
    hashed_password = data['hashedPassword']
    captcha = data['captcha']


    """
    这段代码使用了Python的bcrypt库来生成盐（salt）并将哈希密码与盐一起进行哈希处理。
    bcrypt是一种用于密码哈希和加密的常用方法，可以帮助增加密码的安全性。

    1. `bcrypt.gensalt()`: 这个函数生成一个随机的盐值。
    盐是一个随机的字符串，与密码一起用于生成哈希值。
    每次调用`gensalt()`都会生成一个不同的盐值，增加密码的安全性。

    2. `hashed_password = bcrypt.hashpw(hashed_password.encode('utf-8'), salt)`: 
    这一行代码使用生成的盐（salt）和输入的哈希密码（已经编码为UTF-8格式的字节字符串）来生成哈希密码。
    `bcrypt.hashpw()`函数接受两个参数：要哈希的密码和盐。
    它将这两个值结合在一起并生成一个安全的哈希密码。

    通过使用盐来哈希密码，即使相同的密码在不同用户之间使用，其哈希值也将不同，
    从而增加了密码的安全性，因为相同的密码不会产生相同的哈希值。
    bcrypt还使用内部的加盐和迭代技术来增加密码的安全性。
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(hashed_password.encode('utf-8'), salt)

    # if captcha is not correct
    sql = "SELECT * FROM user_captcha WHERE username = %s AND captcha = %s"
    cursor.execute(sql, (user, captcha))

    results = cursor.fetchall()
    if len(results) == 0:
        return jsonify({"message": "Invalid captcha"}), 401

    print("captcha correct")


    # insert username, salt keypair
    #sql = "INSERT INTO user_salt(username, salt) VALUES ('%s', '%s')" % (user, salt.decode('utf-8'))
    sql = "INSERT INTO user_salt(username, salt) VALUES (%s, %s)"
    if cursor.execute(sql, (user, salt.decode('utf-8'))) == -1:
    #if regist_sql(cursor, sql, db) == -1:
        return jsonify({"message": "user exists"}), 401
    else:
        print("insert salt success")

    # SQL 插入语句
    #sql = "INSERT INTO user_password(username, hashed_password) VALUES ('%s', '%s')" % (user, hashed_password.decode('utf-8'))
    sql = "INSERT INTO user_password(username, hashed_password) VALUES (%s, %s)"
    if cursor.execute(sql, (user, hashed_password.decode('utf-8'))) == 0:
    #if regist_sql(cursor, sql, db) == 0:
        return jsonify({"message": "Registration success!"}), 200
    else:
        return jsonify({"message": "user exists"}), 401

#获取登录参数及处理
@app.route('/login', methods=['POST'])
def getLogin():
    """
    查询数据库以验证用户名和哈希密码是否匹配并存在。

    Returns:
        tuple: 返回包含消息和HTTP状态代码的元组。如果验证成功，消息为'Authentication successful'，状态代码为200。
               如果验证失败，消息为'Authentication failed. Invalid password.'，状态代码为401。
               如果发生意外错误，消息为'unexpected error'，状态代码为401。

    Note:
        此函数执行以下操作：
        1. 连接到数据库，从数据库中检索用户的盐（salt）。
        2. 使用输入的哈希密码和盐验证用户的登录信息。
        3. 如果验证成功，返回消息'Authentication successful'和状态代码200。
        4. 如果验证失败，返回消息'Authentication failed. Invalid password.'和状态代码401。
        5. 如果发生意外错误，返回消息'unexpected error'和状态代码401。

    Example:
        # 使用示例
        data = request.get_json()
        username = data['user']
        hashed_password = data['hashedPassword']
        response, status_code = getLogin()
        if status_code == 200:
            print("认证成功")
            print(response)
        elif status_code == 401:
            print("认证失败")
            print(response)
        else:
            print("发生意外错误")
            print(response)
    """

    """
    这段代码用于建立与数据库的连接并获取数据库游标，以准备执行数据库操作。

    1. `db = pymysql.connect(host="localhost", user="root", password=config("DB_PASSWORD"), database="PROJECT")`:
        通过使用PyMySQL库建立与数据库的连接，提供了数据库主机、用户名、密码和数据库名称等连接信息。

    2. `cursor = db.cursor()`: 使用连接对象创建一个数据库游标。游标是用于执行数据库查询和操作的工具。

    3. `data = request.get_json()`: 从请求中获取JSON格式的数据，通常包含用户名和哈希密码。
        这些数据将用于后续的数据库操作。
    """
    db = pymysql.connect(host="localhost", user="root", password=config("DB_PASSWORD"), database="PROJECT")
    # 使用cursor()方法获取操作游标 
    cursor = db.cursor()
    data = request.get_json()
    username = data['user']
    hashed_password = data['hashedPassword']
    recaptcha_response = data['recaptchaResponse']

    if verify_recaptcha(recaptcha_response)['success'] == False:
        return jsonify({"message": "Invalid captcha"}), 401

    # retrive salt from database
    #sql = "SELECT salt FROM user_salt WHERE username = '%s'" % (username)
    sql = "SELECT salt FROM user_salt WHERE username = %s"
    cursor.execute(sql, (username))
    results = cursor.fetchall()
    if len(results) == 0:
        return jsonify({"message": "user not exists"}), 401
    salt = results[0][0]



    hashed_password = bcrypt.hashpw(hashed_password.encode('utf-8'), salt.encode('utf-8'))
    hashed_password = hashed_password.decode('utf-8')



    # SQL 查询语句
    #sql = "SELECT * FROM user_password WHERE username = '%s' AND hashed_password = '%s'" % (username, hashed_password)
    sql = "SELECT * FROM user_password WHERE username = %s AND hashed_password = %s"
    status = cursor.execute(sql, (username, hashed_password))
    # status = login_sql(cursor, sql, db)
    # 关闭数据库连接
    db.close()

    """
    这段代码用于根据验证的状态返回相应的响应消息和HTTP状态码。

    1. `if status == 0:`: 如果验证状态为0，表示认证成功。
    返回一个包含消息 'Authentication successful' 和HTTP状态码 200（成功）的JSON响应。

    2. `elif status == 1:`: 如果验证状态为1，表示认证失败，密码无效。
    返回一个包含消息 'Authentication failed. Invalid password.' 和HTTP状态码 401（未经授权）的JSON响应。

    3. `else:`: 如果验证状态不是0也不是1，表示发生了意外错误。
    返回一个包含消息 'unexpected error' 和HTTP状态码 401（未经授权）的字符串响应。

    注意：这段代码用于根据认证的状态生成相应的HTTP响应，
    以便客户端了解认证结果并采取适当的操作。
    """
    if status == 0:
        return jsonify({'message': 'Authentication successful'}), 200 
    elif status == 1:
        return jsonify({'message': 'Authentication failed. Invalid password.'}), 401
    else:
        return jsonify({'message': 'unexpected error'}), 401
    

@app.route('/resetpasswd', methods=['POST'])
def resetpasswd():
    """
    重置用户的密码。

    Returns:
        str: 如果重置成功，返回登录页面的HTML；如果重置失败，返回字符串"fail"。

    Note:
        此函数执行以下操作：
        1. 连接到数据库，从数据库中检索用户的盐（salt）。
        2. 使用输入的哈希密码和盐验证用户的登录信息。
        3. 如果验证成功，返回消息'Authentication successful'和状态代码200。
        4. 如果验证失败，返回消息'Authentication failed. Invalid password.'和状态代码401。
        5. 如果发生意外错误，返回消息'unexpected error'和状态代码401。

    Example:
        # 使用示例
        data = request.get_json()
        username = data['user']
        hashed_password = data['hashedPassword']
        response, status_code = getLogin()
        if status_code == 200:
            print("认证成功")
            print(response)
        elif status_code == 401:
            print("认证失败")
            print(response)
        else:
            print("发生意外错误")
            print(response)
    """

    """
    这段代码用于建立与数据库的连接并获取数据库游标，以准备执行数据库操作。

    1. `db = pymysql.connect(host="localhost", user="root",
        password=config("DB_PASSWORD"), database="PROJECT")`:
        通过使用PyMySQL库建立与数据库的连接，提供了数据库主机、用户名、密码和数据库名称等连接信息。
    2. `cursor = db.cursor()`: 使用连接对象创建一个数据库游标。游标是用于执行数据库查询和操作的工具。
    3. `data = request.get_json()`: 从请求中获取JSON格式的数据，通常包含用户名和哈希密码。
        这些数据将用于后续的数据库操作。
    """
    #连接数据库,此前在数据库中创建数据库PROJECT
    db = pymysql.connect(host="localhost", user="root", password=config("DB_PASSWORD"), database="PROJECT")
    # 使用cursor()方法获取操作游标 
    cursor = db.cursor()
    data = request.get_json()
    user = data['user']
    hashed_password = data['hashedPassword']
    captcha = data['captcha']



    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(hashed_password.encode('utf-8'), salt)

    # if captcha is not correct
    #sql = "SELECT * FROM user_captcha WHERE username = '%s' AND captcha = '%s'" % (user, captcha)
    sql = "SELECT * FROM user_captcha WHERE username = %s AND captcha = %s"
    cursor.execute(sql, (user, captcha))
    results = cursor.fetchall()
    if len(results) == 0:
        return jsonify({"message": "Invalid captcha"}), 401

    print("captcha correct")


    # insert username, salt keypair
    #sql = "INSERT INTO user_salt(username, salt) VALUES ('%s', '%s') \
    #    ON DUPLICATE KEY UPDATE salt='%s'" % (user, salt.decode('utf-8'), salt.decode('utf-8'))
    sql = "INSERT INTO user_salt(username, salt) VALUES (%s, %s) \
        ON DUPLICATE KEY UPDATE salt=%s"
    
    if cursor.execute(sql, (user, salt.decode('utf-8'), salt.decode('utf-8'))) == -1:
        return jsonify({"message": "unknown error"}), 401
    else:
        print("insert salt success")

    # SQL 插入语句
    #sql = "INSERT INTO user_password(username, hashed_password) VALUES ('%s', '%s') \
    #    ON DUPLICATE KEY UPDATE hashed_password='%s'" % (user, hashed_password.decode('utf-8'), hashed_password.decode('utf-8'))
    sql = "INSERT INTO user_password(username, hashed_password) VALUES (%s, %s) \
        ON DUPLICATE KEY UPDATE hashed_password=%s"

    try: 
        cursor.execute(sql, (user, hashed_password.decode('utf-8'), hashed_password.decode('utf-8')))
    except Exception as e:
        print(e)
        return jsonify({"message": "unknown error"}), 401
    finally:
        db.close()
        return jsonify({"message": "Password reset successfully!"}), 200



def clear_captcha():
    """
    清除验证码表中的所有数据并定时执行清除操作。

    Args:
        None

    Returns:
        None

    Raises:
        None

    Note:
        这段代码通过每隔5分钟清除user_captcha中的内容，达到验证码有效期为5分钟的效果。
    """
    db = pymysql.connect(host="localhost", user="root", password=config("DB_PASSWORD"), database="PROJECT")
    # 使用cursor()方法获取操作游标
    cursor = db.cursor()
    # 循环执行清除操作
    table_name = 'user_captcha'
    while True:
        try:
            # 每隔5分钟执行一次清除操作
            time.sleep(300)  # 5分钟等待时间

            # 删除表里的所有数据
            delete_query = f"DELETE FROM {table_name}"
            cursor.execute(delete_query)
            db.commit()
            print(f"表 {table_name} 已清除")

        except KeyboardInterrupt:
            # 如果用户按下Ctrl+C，退出循环
            break
 
#使用__name__ == '__main__'是 Python 的惯用法，确保直接执行此脚本时才
#启动服务器，若其他程序调用该脚本可能父级程序会启动不同的服务器
if __name__ == '__main__':
    # 创建一个线程来执行clear_captcha函数
    clear_thread = threading.Thread(target=clear_captcha)
    clear_thread.start()

    app.run(debug=True, host='0.0.0.0', port=5000)
