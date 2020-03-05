##### 签名验签
##### 签名的一般过程：先对数据进行摘要计算，然后对摘要值用私钥进行签名。

##### RSA密钥签名验签
生成私钥。
>zhangsandeiMac:secret zhangsan$ openssl genrsa -out ca.key 2048

导出公钥。
>zhangsandeiMac:secret zhangsan$ openssl rsa -in ca.key -pubout -out ca.pub


私钥签名。
>zhangsandeiMac:secret zhangsan$ openssl dgst -sign ca.key -sha256 -out 1.sign 1.zip 

公钥验签
>zhangsandeiMac:secret zhangsan$ openssl dgst -verify ca.pub -sha256 -signature 1.sign 1.zip 

<br/>

> <br/>
> -------从文件读取公钥------- <br/>
> @param filePath 文件路径 <br/>
> @param size 文件大小 <br/>
> @return 返回密钥 <br/>
> 
<br/>

```
func getPublicKeyRefWithContentsOfFile(_ filePath: String, _ size: size_t) -> SecKey
```

<br/>

> <br/>
> -------从文件读取私钥------- <br/>
> @param filePath 文件路径 <br/>
> @param password 文件密码 <br/>
> @return 返回密钥 <br/>
> 
<br/>

```
func getPrivateKeyRefWithContentsOfFile(_ filePath: String, _ password: String) -> SecKey
```
<br/>

> <br/>
> -------RSA 公钥加密------- <br/>
> @param data 明文，待加密的数据 <br/>
> @param keyRef 公钥 <br/>
> @return 密文，加密后的数据 <br/>
> 
<br/>

```
func encryptData(_ data: Data, _ pubKey: SecKey, _ padding: SecPadding) -> Data 
```

<br/>

> <br/>
> -------RSA 私钥解密------- <br/>
> @param data 密文，需要解密的数据 <br/>
> @param keyRef 私钥 <br/>
> @return 明文，解密后的字符串 <br/>
>  
<br/>

```
func decryptData(_ data: Data, _ priKey: SecKey, _ padding: SecPadding) -> Data
```

<br/>

> <br/>
> -------私钥签名------- <br/>
> @param plainData 明文 <br/>
> @param privateKey 私钥文件 <br/>
> @return 返回签名数据 <br/>
> 
<br/>

```
func signData(_ dataToSign: Data, _ priKey: SecKey, _ padding: SecPadding) -> Data
```

<br/>

> <br/>
> -------公钥校验签名------- <br/>
> @param plainData 明文 <br/>
> @param signData 签名文件 <br/>
> @param publicKey 公钥文件 <br/>
> @return 验签成功返回true，失败返回false <br/>
> 
<br/>

```
func verifyData(_ plainData: Data, _ signData: Data, _ pubKey: SecKey, _ padding: SecPadding)
```

```swift
    let pubString: String = Bundle.main.path(forResource: "ca.pub", ofType: nil)!
    let pubkey: SecKey = RSAcryptor().getPublicKeyRefWithContentsOfFile(pubString, 2048)

    let priString: String = Bundle.main.path(forResource: "ca.key", ofType: nil)!
    let prikey: SecKey = RSAcryptor().getPrivateKeyRefWithContentsOfFile(priString, "1234")

    let string: String = "phbtttttt@gmail.com"

    let plainData: Data = string.data(using: .utf8)!
    let cryptData = RSAcryptor().encryptData(plainData, pubkey, SecPadding.PKCS1)
    let decryptData = RSAcryptor().decryptData(cryptData, prikey, SecPadding.PKCS1)

    let restr: String = String.init(data: decryptData, encoding: .utf8)!
    print("\(restr)")


    let signData = RSAcryptor().signData(plainData, prikey, SecPadding.PKCS1SHA256)

    assert(RSAcryptor().verifyData(plainData, signData, pubkey, SecPadding.PKCS1SHA256), "验证签名失败") 
```
