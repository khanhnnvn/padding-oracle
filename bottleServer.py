#!/usr/bin/python
 # -*- coding: utf-8 -*- 
from bottle import route, run, request, abort
from Crypto.Cipher import AES, Blowfish
from PaddingOracle import *
from Encryption import *
import sys

__author__ = 'khanhnnvn@gmail.com'
__url__ = ''

@route('/')
def index():
    if not request.query.cipher:
        return '''
            <center>
            <div class="mainpage">
                <div class="topbaner">
                    <div id="headerTop">
                        
            <img alt="Dmo" src="http://home.actvn.edu.vn/Upload/svda/hoc-vien-mat-ma.jpg" class="logoTop">
            <center><font size="6">Tiểu luận</font></center>
            <center><font size="6"><i>"Thực hành tấn công PaddingOracle"</i> </font></center>
            <br>

            <center>
            <font size="6"><a href="/generate">generate cipher</a><br/></font>
            <font size="6"><a href="/?cipher=eb2f2f80dd49cf6fd230683ee174d8f4e4f0726f528e4822241c0004616ca8ba6c145cdf78fb8461ded213d0b60fef0641c6869bbccbb84ca38958f5ec3eb43fa465b559d851c6bf342e479bc30f6701">decrypt sample</a></font>
            </center>
            <br>
            <center><font size="4">Giáo viên hướng dẫn: TS Đặng Minh Tuấn</font></center>
            <center><font size="4">Thành viên nhóm: </font></center>
            <center><font size="4">Nguyễn Ngọc Khánh </font></center>
            <center><font size="4">Trần Thanh Hà </font></center>
            <center><font size="4">Bùi Thái Dương</font></center>
            <center><font size="4">Trần Bá Phúc</font></center>
        '''
    else:
        ctext = request.query.cipher
        if len(ctext) % (AES.block_size * 2) != 0:
            return 'Kidding me? I can\'t decrypt an odd-length ciphertext, guys!'
        elif len(ctext) / (AES.block_size * 2) == 1:
            return 'Nope! Please tell me how to decrypt message with one block only.'
        else:
            iv = ctext[:AES.block_size * 2]
            Oracle = AESOracle(iv.decode('hex'))
            if Oracle.do_oracle(ctext.decode('hex')):
                abort(404, "Resource not found")
            else:
                # return HTTPResponse(status=403, body='Nope')
                abort(403, "Access denied")

@route('/generate')
def generate():
    return '''
        <center>
        <form action="/generate" method="post">
            <input name="plaintext" type="textarea"/>
            <input value="generate" type="submit"/>
        </form>
        </center>
    '''

@route('/generate', method='POST')
def do_generate():
    plaintext = request.forms.get('plaintext')
    ciphertext = AESEncrypt(pad(plaintext, AES.block_size))
    return '''
        <a href="/?cipher={}">{}</a>
    '''.format(ciphertext, ciphertext)

@route('<:re:^/(.*?)$>')
def anything_else():
    return 'Nothing here, go back'
if __name__ == '__main__':
    if len(sys.argv) > 1:
        port = sys.argv[1]
    else:
        port = 8080
    run(host='0.0.0.0', port=port, debug=False)
