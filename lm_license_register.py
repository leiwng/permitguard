# -*- coding: utf-8 -*-
"""根据用户信息和授权使用年限生成许可证文件

Usage:
    - 在公司License Management服务器上运行该模块
    - 输入授权使用年限
    - 将生成的许可证文件复制两份:
        - 一份发送给用户,并保存到产品安装目录的license_manager目录下
        - 一份保存到公司的License Management服务器的许可证备份目录下的该用户的子目录下(以用户名称命名)

Author: Lei Wang
Date: April 10, 2024
"""



__author__ = "王磊"
__copyright__ = "Copyright 2024 四川科莫生医疗科技有限公司"
__credits__ = ["王磊"]
__maintainer__ = "王磊"
__email__ = "lei.wang@kemoshen.com"
__version__ = "0.0.1"
__status__ = "Development"


import os
import sys
import json
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


if __name__ == "__main__":

    # 如果命令行参数不是2个,则提示用户输入用户信息文件的路径
    if len(sys.argv) != 2:
        print("请在命令行中输入用户信息文件的路径")
        sys.exit(1)

    # 读取用户信息文件路径
    usr_info_fp = sys.argv[1]
    # 判断文件是否存在
    if not os.path.exists(usr_info_fp):
        print("用户信息文件不存在")
        sys.exit(1)
    # 读取用户信息文件
    with open(usr_info_fp, 'r', encoding="utf-8") as f:
        usr_info = json.load(f)

    # 显示用户信息共确认
    print("请确认以下用户信息是否正确")
    print(usr_info)

    # 输入回车表示确认，输入'q'表示退出
    confirm = input("确认用户信息(Yes/No)?")
    if confirm.lower() not in ['yes', 'y']:
        print("用户信息不正确,未通过确认,退出.")
        sys.exit(1)
    else:
        print("用户信息正确,继续生成许可证文件.")

    # 输入授权使用年限
    license_year = input("请输入许可年限:")

    # 判断授权使用年限是否是数字
    if not license_year.isdigit():
        print("授权使用年限必须是数字")
        print("输入错误,退出.")
        sys.exit(1)

    # 授权使用年限转换为整数
    license_year_int = int(license_year)

    # 计算许可证到期时间
    # 多加30天，以便用户有时间更新许可证，也给注册时间给出了缓冲
    available_days = license_year_int * 365 + 31
    license_expiry_date = (datetime.now() + timedelta(days=available_days)).isoformat()
    # license_expiry_date = (datetime.now() + timedelta(days=available_days)).date()

    # 将许可到期时间写入用户信息
    usr_info["expiry_date"] = license_expiry_date
    print(usr_info)

    # 下面将分多步对用户信息进行签名，并生成许可证文件
    # 从当前目录下读入公司争对SerumSage的私钥
    if not os.path.exists("kms_serumsage_private_key.pem"):
        print("公司SerumSage产品私钥文件在当前目录下不存在")
        sys.exit(1)
    # 读取公司SerumSage产品私钥
    with open("kms_serumsage_private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    # 签名用户信息
    # 先把用户信息转换为JSON字符串
    usr_info_json = json.dumps(usr_info)
    # 将JSON字符串编码为字节
    usr_info_bytes =usr_info_json.encode("utf-8")
    signature = private_key.sign(
        usr_info_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # 将许可证信息和签名写入许可证文件
    license_fp = "license.lic"
    with open(license_fp, "w", encoding="utf-8") as f:
        json.dump({
            "license_info": usr_info,
            "signature": signature.hex()
        }, f)
