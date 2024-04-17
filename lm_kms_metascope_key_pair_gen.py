# -*- coding: utf-8 -*-
"""生成科莫生MeteScope产品的公钥

Usage:
    - 在公司License Management服务器上运行该模块
    - 公钥一旦生成后，不要再执行该模块，切记！！！
    - 生成的公钥文件随产品一起发布

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


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


if __name__ == "__main__":

    # 生成密钥对
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    # 私钥保存到文件
    with open("kms_metascope_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        ))

    # 公钥保存到文件
    with open("kms_metascope_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
