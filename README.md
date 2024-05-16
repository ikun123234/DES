# DES算法的实现

scu cyberspace security

四川大学应用密码学实验 具体要求如下：

![image-20240516161129511](https://raw.githubusercontent.com/ikun123234/image_repo/main/image/image-20240516161129511.png)

![image-20240516161149568](https://raw.githubusercontent.com/ikun123234/image_repo/main/image/image-20240516161149568.png)

## 实验结果

`crypt.exe -h 查看相关帮助`

![image-20240516161420124](https://raw.githubusercontent.com/ikun123234/image_repo/main/image/image-20240516161420124.png)

`crypt.exe -p a_plain1_text -k a_key -m 0 -c ecb_1_encrypt 测试数据进行ECB加密`

![image-20240516161556227](https://raw.githubusercontent.com/ikun123234/image_repo/main/image/image-20240516161556227.png)

`crypt.exe -p a_plain1_text -v a_initvec -k a_key -m 1 -c cbc_1_encrypt 测试数据进行CBC加密`

![image-20240516161721407](https://raw.githubusercontent.com/ikun123234/image_repo/main/image/image-20240516161721407.png)

`crypt.exe -p a_plain1_text -v a_initvec -k a_key -m 2 -c cfb_1_encrypt 测试数据进行CFB加密`

![image-20240516161852366](https://raw.githubusercontent.com/ikun123234/image_repo/main/image/image-20240516161852366.png)

`crypt.exe -p a_plain1_text -v a_initvec -k a_key -m 3 -c ofb_1_encrypt 测试数据进行OFB加密`

![image-20240516161940044](https://raw.githubusercontent.com/ikun123234/image_repo/main/image/image-20240516161940044.png)

## 自选数据进行十次加密

加密结果如下所示

![image-20240516162058052](https://raw.githubusercontent.com/ikun123234/image_repo/main/image/image-20240516162058052.png)

通过实验数据可知，CFB模式加密时间大概是其他加密模式的10倍左右，其他三种模式的加密时间类似，加密效率类似，至于时间存在波动，可能是因为后期进行了多线程运行，导致效率降低