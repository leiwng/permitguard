# -*- coding: utf-8 -*-
"""许可证验证模块
验证许可证是否有效.
 - 许可证信息是否有效(用户安装产品主机硬件信息,用户名称,许可过期时间)
 - 产品许可是否过期

Usage:
    - 运行于产品软件中
    - 提供验证API接口

Author: Lei Wang
Date: April 16, 2024
"""


__author__ = "王磊"
__copyright__ = "Copyright 2024 四川科莫生医疗科技有限公司"
__credits__ = ["王磊"]
__maintainer__ = "王磊"
__email__ = "lei.wang@kemoshen.com"
__version__ = "0.0.1"
__status__ = "Development"


from lm_comm_lib import verify_license


if __name__ == "__main__":
    # for test
    license_fp = "license2.lic"
    encoding = "utf-8"
    public_key_fp = "kms_serumsage_public_key.pem"
    result, err_msg, usr_name, expiry_date = verify_license(license_fp, encoding, public_key_fp)
