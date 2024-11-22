import os
from distutils.command.config import config
from configparser import ConfigParser
import time
from fileinput import filename

import qrcode
from flask import Flask, request, send_from_directory, render_template_string, render_template

app = Flask(__name__)
conf = ConfigParser()
conf.read('config.ini')
upload_folder = conf['path']['file_path']
os.makedirs(upload_folder, exist_ok=True)

# HTML模板，用于上传文件
succ=open(conf['path']['success_template'],'r',encoding='utf-8')
succ=succ.read()
up=open(conf['path']['upload_template'],'r',encoding='utf-8')
up=up.read()
print('模板文件:',conf['path']['success_template'],'和',conf['path']['upload_template'])

# 首页路由，提供文件上传界面
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')  # 使用 get 方法，避免 KeyError
        if file:
            filepath = os.path.join(upload_folder, file.filename)
            file.save(filepath)
            return render_template_string(succ , filename=file.filename)
        else:
            return "No file uploaded", 400  # 文件未上传的处理
    return render_template_string(up)

# 文件下载路由
@app.route('/files/<filename>')
def uploaded_file(filename):
    return send_from_directory(upload_folder, filename)

# 生成二维码的路由
@app.route('/qr')
def qr_code():
    # 生成指向首页的二维码
    url = request.host_url
    qr = qrcode.make(url)
    qr.save('qr_code.png')
    return '<img src="/qr_code.png" alt="QR Code"/><br><a href="/">Upload a File</a>'
# 显示logo的路由
@app.route('/logo.png')
def serve_logo_code():
    return send_from_directory(os.getcwd(), 'static/img/logo.png')
# 显示二维码的路由
@app.route('/qr_code.png')
def serve_qr_code():
    return send_from_directory(os.getcwd(), 'qr_code.png')
def config_():
    print('正在读取配置文件....')

    time.sleep(5)
    conf = ConfigParser()
    conf.read('config.ini')
    ip=conf['ip']['ip_']
    print('ip:',ip)
    port=conf['ip']['port']
    print('port:',port)


    print('正在唤醒flask框架.....')
    time.sleep(2)
    print('框架启动成功!')
    print('如出现套字节错误请检查ip和端口占用情况.')
    return ip,port
if __name__ == '__main__':
    ip, port=config_()
    # 启动Flask开发服务器
    app.run(host=ip, port=int(port),debug=False)

