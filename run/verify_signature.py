import dsa

def run():
    """消息签名验证
        通过启动run()执行以下功能：
        -----------------------
            1） 通过访问data/message.txt获取消息和签名对;

            2） 对签名进行验证

    """
    # 获取消息-签名对
    with open("../data/message.txt", "r", encoding="utf-8") as msg:
        sign_list = [x.split(":")[1].strip() for x in msg.readlines()]
        m = sign_list[0]
        r = int(sign_list[1])
        s = int(sign_list[2])
        sign = (m, (r, s))

    # 获取公钥
    with open("../data/public_key.txt", "r") as pub:
        pub_keys = [x.split(":")[1].strip() for x in pub.readlines()]
        p = int(pub_keys[0])
        q = int(pub_keys[1])
        g = int(pub_keys[2])
        public_key = int(pub_keys[3])

    # 传入公钥和签名对，进行验证
    flag = dsa.verify(sign, g, public_key, p, q)
    if flag==True:
        print("签名验证成功！")
    elif flag==False:
        print("签名验证失败！")

run()