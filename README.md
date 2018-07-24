# DSA_Threshold
(t,n) threshold signature based on DSA

# 声明：
*`threshold.py`使用python `tss-0.1`修改得出，tss-0.1地址：https://pypi.org/project/tss/*<br>
*`dsa.py`模块中的`findModReverse`函数出自论坛，由于遗忘了出处地址，在此致歉作者，如有侵权，请联系我立即删除。*<br>
*仅用于学习研究、请不要应用到实际生产中，防止出现安全问题。*<br>

# 文件介绍：
    /: 主文件，存放主要功能模块和说明文件：
            dsa.py: 用于实现基于离散对数的数字签名
            thresshold.py: 用于实现基于拉格朗日插值法的(t,n)门限 (基于shamir的(t,n)门限)

            其余文件：
            README.txt: 参考文件
            todo.py: 下一步计划

    /data/: 主要存放数据：
            /private_keys/: 存放通过(t,n)门限分发的密钥分片
            message.txt: 签名产生的"消息-签名对"
            public_key.txt: 公开信息：p, q, g, public_key

    /run/: 存放主要的运行模块:
            gen_key_and_threshold.py: 产生公钥(p,q,g,public_key) 私钥private_keys，并将私钥加密后分片存储，公钥公开
            signature_message.py: 签名
            verify_signature.py: 验证签名

    /test/: 测试文件夹，可忽略
            dsa_test.py: 测试dsa.py模块
            threshold_test.py: 测试threshold.py模块（外部模块，为tss安装包文件修改，主要定义(t,n)分片）


# 运行顺序：
    gen_key_and_threshold,py
    signature_message.py
    verify_signature.py

##### 先运行`gen_key_and_threshold.py`生成密钥，公钥保存至`./data/public_key.txt,`私钥通过分片以密文形式保存至`private_keys`文件夹，实现(t,n)门限
##### 可以通过查看文件的变化确定公私钥的变化
##### 再运行`signature_message.py`对输入消息进行签名，消息签名对放入`./data/message.txt`
##### 最后运行 `verify_signature`对签名进行验证
##### 验证成功以后通过对`message.txt`中的消息进行修改，再次验证会验证失败，实现对消息完整性的检测
