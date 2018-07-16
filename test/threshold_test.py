import threshold
import random
#
# shares = threshold.share_secret(3,25,"my_secret",'id1')
# print(shares)
# print(len(shares))
#
#
# share = []
#
# for i in range(3):
#     l = random.randint(0,25)
#     share.append(shares[l])
#     print(shares[l])
#
# secret = str(threshold.reconstruct_secret(shares,), encoding='utf-8')
# print(secret)
shares = threshold.share_secret(3,5,"my_secret",'id1')