import dsa
import threshold
import pickle
import os
import shutil

def run():
    """生成公私钥
        通过启动run()执行以下功能：
        -----------------------
            1） 生成p, q, g, public_key, private_key;

            2） 将公开信息：p, q, g, public_key以公开方式存入：dsa/data/public_key.txt文件

            3） 对private_key运用基于Shamir的(t,n)门限方式, 对生成的t_shares保存到private_keys文件夹

    """

    # 取消注释则改为手动限定范围
    # min_num = int(input("请限定生成p,q的范围下限："))
    # max_num = int(input("请限定生成p,q的范围上限："))

    min_num = 10000000
    max_num = 999999999
    # 调用p,q生成函数
    pq = dsa.gen_pq(min_num,max_num)
    p = pq[0]
    q = pq[1]

    # 测试签名的正确性，取消注释，则尝试不符合规则的q就会签名失败
    # q = 1000

    print("######### 开始生成公钥和私钥 ##########")
    print("生成p：{p}\n生成q：{q}".format(p=p,q=q))

    # 生成私钥、公钥、g, 密钥均为int型，存储时转换为字符串做处理，在取用时换回int
    keys = dsa.generateKeys(p, q)
    private_key = keys[0]
    public_key = keys[1]
    g = keys[2]

    # 将公开信息"public_key"和"g""p""q"写入文件
    pub_key = ["p:", str(p) ,"\n",\
        "q:", str(q), "\n", \
        "g:",str(g), "\n", \
        "public_key:",str(public_key),"\n",\
        ]
    with open(r"../data/public_key.txt", "w") as pub:
        pub.writelines(pub_key)
        pub.close()
        print("公钥已写入：dsa/data/public_key.txt")


    # 对私钥分片，实现(t,n)门限
    print("\n######### 开始对密钥进行分片 ##########")
    t = int(input("请设置t值："))
    n = int(input("请设置n值："))
    id = "id"
    # id = input("设置分片标识(0-16 bytes)：")
    flag = False
    shares = threshold.share_secret(t, n, str(private_key), id)

    # 判断私钥文件夹是否存在，存在则删除重建，不存在新建
    path = r"../data/private_keys/"
    if os.path.exists(path,):
        shutil.rmtree(path,)
        os.makedirs(path,)
    else:
        os.makedirs(path,)

    # 将生成的私钥分片以密文的方式保存至本地
    for each in range(1, len(shares)+1):
        fragmentation_name = path + "shares_key_" + str(each)
        try:
            with open(fragmentation_name, "wb") as f:
                pickle.dump(shares[each-1], f,)
            flag = True

        except FileNotFoundError as e:
            print("Error: ", e)
            flag = False

    # 通过flag判断分发是否成功
    if flag:
        info = "私钥分发成功:(t,n)=(" + str(t) + "," + str(n) +")！"
        print(info)
        print("私钥分片已写入：dsa/data/private_key文件夹")

run()