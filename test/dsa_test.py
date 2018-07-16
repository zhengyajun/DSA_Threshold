import  dsa

def main():
    """主函数"""

    # p = int(input("请输入p："))
    # q = int(input("请输入q："))

    # 调用p,q生成函数
    pq = dsa.gen_pq(1000000,99999999)
    p = pq[0]
    q = pq[1]

    # 测试签名的正确性，更改不符合规则的q就会签名失败
    # q = 1000
    print("生成p：{p}\n生成q：{q}".format(p=p,q=q))

    # 生成私钥、公钥、g
    keys = dsa.generateKeys(p, q)
    private_key = keys[0]
    # print(type(private_key), private_key)
    public_key = keys[1]
    g = keys[2]

    # 返回 消息-签名对 (m,(r, s))
    sign = dsa.signature(g, private_key, p, q)

    # 返回True或False
    flag = dsa.verify(sign,g, public_key, p, q)
    if flag==True:
        print("Verify Success!")
    elif flag==False:
        print("Verify invalid")


main()

"""测试用素数对
21
P: 108236014372587025560068551178811464567014495778053
Q: 1288523980626036018572244656890612673416839235453

15 
P: 1419065958850019997740008759902916496762666967259
Q: 78836997713889999874444931105717583153481498181

14 10
P: 1230708641368757453241028556973036798270961840363
Q: 8918178560643169951021946065022005784572187249

p：11111111111111111111111
q：513239

23333333333333333
46153

p：100000042067
q：900139
"""
