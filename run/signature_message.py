import dsa
import threshold
import random
import os
import pickle
import time, sys

def run():
    """消息签名
        通过启动run()执行以下功能：
        -----------------------
            1） 通过访问private_keys文件夹中的指定或随机分配的私钥分片进行私钥重组;

            2） 通过私钥和部分公钥对消息进行签名，将消息签名对写入文件/data/message.txt

    """

    # 依靠分发密钥合成private_key
    print("######### 重组私钥 #########")
    t_key = []
    temp = []

    # 随机读取t个私钥分片
    path = r"../data/private_keys/"
    if not os.path.exists(path,):
        print("Error:Confirm the existence of the private_keys")

    else:
        n = len(os.listdir(path))
        if not n:
            print("Error:Is the private_keys empty? ")

        else:
            t = int(input("请输入重组私钥个数："))
            if t > n:
                print("Error: t > n")
            elif t==0:
                print("Error: \"t\"不可以为 0")
            else:
                # 读取t个分片
                for i in range(1, t+1):
                    sys.stdout.write('\r')
                    sys.stdout.write("%s%% |\t " %(int(i/t*100)))

                    # 判断分片id（j）是否重复读取
                    j = random.randint(1, n)
                    while j in temp:
                        j = random.randint(1,n)
                    temp.append(j)

                    # 生成分片列表
                    private_key_share = path + "shares_key_" + str(j)
                    with open(private_key_share, "rb") as f:
                        share = pickle.load(f)
                        print("读取" + private_key_share + "成功！")
                    t_key.append(share)

                # 调用(t,n)重组函数，合成私钥
                try:
                    private_key = int(threshold.reconstruct_secret(t_key,))
                    # private_key = int(threshold.reconstruct_secret(t_key, strict_mode=False))  # 不允许同样的分片被利用两次以上
                    # print(private_key)
                    print("private_key重组成功")

                    # 读取p, q, g
                    with open("../data/public_key.txt") as pub:
                        pub_keys = [x.split(":")[1].strip() for x in pub.readlines()]
                        p = int(pub_keys[0])
                        q = int(pub_keys[1])
                        g = int(pub_keys[2])

                    print("\n########## 签名 ###########")
                    m = input("请输入要签名的消息：")

                    # 消息签名
                    sign = dsa.signature(g, private_key, p, q, m)
                    sign_list = [
                        "消息m:", str(sign[0]), "\n",
                        "待比对信息r:", str(sign[1][0]), "\n",
                        "验证参数s:", str(sign[1][1]), "\n",
                    ]

                    # 将消息-签名对保存，供验证程序使用
                    with open("../data/message.txt", "w", encoding="utf-8") as msg:
                        msg.writelines(sign_list)
                    print("签名成功！")
                    print("消息及签名信息对已写入:dsa/data/message.txt")

                except threshold.TSSError as e:
                    print("Error: ",e)   # t过小

run()