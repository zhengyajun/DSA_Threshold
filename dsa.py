import random as rn
import hashlib
import math
"""这些系统参数构成DSA的密钥空间 
    K={p, q, g, public_key, private_key, H}, 
    （p, q, g, public_key, H）为公开密钥, 
    private_key为私钥 
    H为哈希方法
"""
def is_prime(number):
    """验证是否是素数
        PARAMS
        ------
            number: (int) 待判断值

        RETURNS
        -------
            bool  Ture or False
    """
    if number > 1:
        if number == 2:
            return True
        if number % 2 == 0:
            return False
        for current in range(3, int(math.sqrt(number) + 1), 2):
            if number % current == 0:
                return False
        return True
    return False


def gen_pq(min=10000000, max=999999999):
    """生成一定范围的pq
    :param:
        min: (int) 限定产生素数的范围起始值
        max: (int) 限定产生素数的范围结束值

    :attention
    ----------
        根据电脑性能选择，建议在8到9位之间，否则后续加密计算一般电脑吃力
        （这一点有待完善，不能支持超大数计算）

    :return:
        pq_pair: (tuple) p,q
    """
    while True:
        num = rn.randint(min, max)
        if is_prime(num):
            pq_pair = None
            for i in range(3,int(math.sqrt(num))):
                if (((num-1) % i) == 0):
                    if is_prime(i) and i>200:                            # 如果生成的q太小，会造成计算g时指数太大，计算机算不出来
                        pq_pair = (num,i)
            # print(pq_pair)
            if pq_pair != None:
                return(pq_pair)


def findModReverse(a,m):
    """ 通过扩展欧几里得算法求模逆计算模逆

        PARAMS
        ------
            a：(int) 需要求模逆的数
            m: (int) 模数

        RETURNS
        -------
            u1%m 模逆值
    """
#    if gcd(a,m)!=1:
#       return None
    u1,u2,u3 = 1,0,a
    v1,v2,v3 = 0,1,m
    while v3!=0:
        q = u3//v3
        v1,v2,v3,u1,u2,u3 = (u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
    return u1%m

def generateKeys(p, q):
    """ 用于产生私钥“private_key” 和公钥“publick_key”

        PARAMS
        ------
            p: (int) 长度为l比特的大素数P

            q: (int) 长度为m比特，为(P-1)的一个素因子

        RETURNS
        -------
            (private_key, public_key, g) 私钥:private_key 及公钥:public_key, g
    """
    private_key = rn.randint(1,q)

    while True:
        h = rn.randint(1,p-1)
        # print(h)
        g = (h**int(((p-1)/q))) % p
        if g > 1:
            break

    public_key = g**private_key % p
    # print ("Private Key = { ",g,",", private_key, " }")
    # print ("Public Key = { ",g,",", public_key, " }")
    print("公私钥生成成功！")
    return (private_key, public_key, g)


def messageDigest(m):
    """用于计算消息哈希值，采用sha_1()

        PARAMS
        ------
            m: (str) 待签名消息

        RETURNS
        -------
            hashm 十进制的消息摘要值
    """

    sha = hashlib.sha1()
    sha.update(m.encode())
    hashm = int(sha.hexdigest(),16)
    print ("信息摘要 : ",hashm)
    return hashm


def signature(g, private_key, p, q, m):
    """消息签名

        PARAMS
        ------
            g: (int) 公开密钥之一

            private_key： (int) 私钥

            p, q： (int) 大素数对

            m: 待签名消息

        RETURNS
        -------
            (m, (r, s)) 消息-签名对
    """

    hashm = messageDigest(m)
    k = rn.randint(1,q)
    r = ((g**k) % p) % q
    k_ni = findModReverse(k, q)     # 模逆
    s = (k_ni * (hashm + private_key*r)) % q # 摘要信息
    # print ("Digital Signature : ( ",r,",",s,")")
    print("签名消息：{0}， 生成待验证信息r：{1}, 签名信息对(r,s)=({2},{3})".format(m, r, r, s))
    return (m, (r, s))


def verify(sign, g, public_key,p, q,):
    """验证签名

        PARAMS
        ------
            sign: (tuple) 消息-签名对

            g: (int) 公开密钥之一

            public_key: (int) 公钥

            p, q： (int) 大素数对

        RETURNS
        -------
            hashm 十进制的消息摘要值
    """
    print("\n########## 验证 ###########")
    m = sign[0]
    r = sign[1][0]
    s = sign[1][1]
    print("收到消息：{0}， 签名对(r,s):({1},{2})".format(m, r, s))

    hashm = messageDigest(m)
    s_ni = findModReverse(s, q)
    w = s_ni % q
    u1 = (hashm * w) % q
    u2 = r*w % q
    v = (((g**u1) * (public_key**u2)) % p) % q
    # print(p, q,m,r,s,s_ni,w,u1,u2,v)
    print("生成验证信息v：{1}".format(m,v))
    if v == r:
        print("v = r")
        return True
    else:
        print("v != r")
        return False


