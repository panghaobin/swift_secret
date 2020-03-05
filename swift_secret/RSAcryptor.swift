//
//  RSAcryptor.swift
//  swift_secret
//
//  Created by 张三 on 2020/3/3.
//  Copyright © 2020 phbtttttt@gmail.com. All rights reserved.
//

import Foundation
import CommonCrypto


func sha1(data : Data) -> Data {
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA1_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return Data(hash)
}
func sha224(data : Data) -> Data {
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA224_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA224($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return Data(hash)
}
func sha256(data : Data) -> Data {
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return Data(hash)
}
func sha384(data : Data) -> Data {
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA384_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA384($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return Data(hash)
}
func sha512(data : Data) -> Data {
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA512_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA512($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return Data(hash)
}
struct RSAcryptor {
    
    
    /**
    * -------从文件读取公钥-------
    @param filePath 文件路径
    @param size 文件大小
    @return 返回密钥
    */
    func getPublicKeyRefWithContentsOfFile(_ filePath: String, _ size: size_t) -> SecKey {
        var pubKey: SecKey?
        var pemStr: String?
        do {
            try pemStr = String(contentsOfFile: filePath)
        } catch {
            print(error)
        }
        
        pemStr = pemStr?.replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
        pemStr = pemStr?.replacingOccurrences(of: "\r", with: "")
        pemStr = pemStr?.replacingOccurrences(of: "\n", with: "")
        pemStr = pemStr?.replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
        let dataPubKey = Data(base64Encoded: pemStr!)!
        let attributes: [String:Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: size,
        ]
        pubKey = SecKeyCreateWithData(dataPubKey as CFData, attributes as CFDictionary, nil)
        return pubKey!
    }
    
    /**
    * -------从文件读取私钥-------
    @param filePath 文件路径
    @param password 文件密码
    @return 返回密钥
    */
    func getPrivateKeyRefWithContentsOfFile(_ filePath: String, _ password: String) -> SecKey {
        var priKey: SecKey?
        var pemStr: String?
        do {
            try pemStr = String(contentsOfFile: filePath)
        } catch {
            print(error)
        }
        pemStr = pemStr?.replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
        pemStr = pemStr?.replacingOccurrences(of: "\r", with: "")
        pemStr = pemStr?.replacingOccurrences(of: "\n", with: "")
        pemStr = pemStr?.replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
        let dataPubKey = Data(base64Encoded: pemStr!)!
        let attributes: [String:Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecImportExportPassphrase as String: password,
        ]
        priKey = SecKeyCreateWithData(dataPubKey as CFData, attributes as CFDictionary, nil)
        return priKey!
    }
    
    /**
    * -------RSA 公钥加密-------
    @param data 明文，待加密的数据
    @param keyRef 公钥
    @return 密文，加密后的数据
    */
    
    func encryptData(_ data: Data, _ pubKey: SecKey, _ padding: SecPadding) -> Data {

        let blockSize = SecKeyGetBlockSize(pubKey) * MemoryLayout<UInt8>.alignment
        
        var maxChunkSize: Int
        switch padding {
        case []:
            maxChunkSize = blockSize
        case .OAEP:
            maxChunkSize = blockSize - 42
        default:
            maxChunkSize = blockSize - 11
        }
        
        var decryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
        (data as NSData).getBytes(&decryptedDataAsArray, length: data.count)
        
        var encryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < decryptedDataAsArray.count {
            
            let idxEnd = min(idx + maxChunkSize, decryptedDataAsArray.count)
            let chunkData = [UInt8](decryptedDataAsArray[idx..<idxEnd])
            
            var encryptedDataBuffer = [UInt8](repeating: 0, count: blockSize)
            var encryptedDataLength = blockSize
            
            let status = SecKeyEncrypt(pubKey, SecPadding.PKCS1, chunkData, chunkData.count, &encryptedDataBuffer, &encryptedDataLength)
            
            assert(status == noErr, "SecKeyEncrypt fail. Error Code: \(status)")
            
            encryptedDataBytes += encryptedDataBuffer
            
            idx += maxChunkSize
        }
        
        let encryptedData = Data(bytes: UnsafePointer<UInt8>(encryptedDataBytes), count: encryptedDataBytes.count)
        return encryptedData
    }
    
    /**
    * -------RSA 私钥解密-------
    @param data 密文，需要解密的数据
    @param keyRef 私钥
    @return 明文，解密后的字符串
    */
    func decryptData(_ data: Data, _ priKey: SecKey, _ padding: SecPadding) -> Data {
        let blockSize = SecKeyGetBlockSize(priKey) * MemoryLayout<UInt8>.alignment
               
        var encryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
        (data as NSData).getBytes(&encryptedDataAsArray, length: data.count)

        var decryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < encryptedDataAsArray.count {
           
           let idxEnd = min(idx + blockSize, encryptedDataAsArray.count)
           let chunkData = [UInt8](encryptedDataAsArray[idx..<idxEnd])
           
           var decryptedDataBuffer = [UInt8](repeating: 0, count: blockSize)
           var decryptedDataLength = blockSize
           
           let status = SecKeyDecrypt(priKey, padding, chunkData, idxEnd-idx, &decryptedDataBuffer, &decryptedDataLength)
           assert(status == noErr, "SecKeyEncrypt fail. Error Code: \(status)")
           decryptedDataBytes += [UInt8](decryptedDataBuffer[0..<decryptedDataLength])
           
           idx += blockSize
        }

        let decryptedData = Data(bytes: UnsafePointer<UInt8>(decryptedDataBytes), count: decryptedDataBytes.count)
        
        return decryptedData
    }
    
    /**
    * -------私钥签名-------
    @param plainData 明文
    @param privateKey 私钥文件
    @return 返回签名数据
    */
    
    func signData(_ dataToSign: Data, _ priKey: SecKey, _ padding: SecPadding) -> Data {
        var digest: Data = Data()
        switch padding {
        case .PKCS1SHA1:
            digest = sha1(data: Data())
        case .PKCS1SHA224:
            digest = sha224(data: Data())
        case .PKCS1SHA256:
            digest = sha256(data: Data())
        case .PKCS1SHA384:
            digest = sha384(data: Data())
        case .PKCS1SHA512:
            digest = sha512(data: Data())
        default:
            digest = sha1(data: Data())
        }
        let blockSize = SecKeyGetBlockSize(priKey) * MemoryLayout<UInt8>.alignment
        let maxChunkSize = blockSize - 11
        
        assert(digest.count <= maxChunkSize, "digest's size no match")
        
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        (digest as NSData).getBytes(&digestBytes, length: digest.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: blockSize)
        var signatureDataLength = blockSize
        
        let status = SecKeyRawSign(priKey, padding, digestBytes, digestBytes.count, &signatureBytes, &signatureDataLength)
        
        assert(status == noErr, "Signature fail. Error Code: \(status)")
        
        let signatureData = Data(bytes: UnsafePointer<UInt8>(signatureBytes), count: signatureBytes.count)
        return signatureData
    }

    /**
    * -------公钥校验签名-------
    @param plainData 明文
    @param signData 签名文件
    @param publicKey 公钥文件
    @return 验签成功返回YES，失败返回NO
    */
    func verifyData(_ plainData: Data, _ signData: Data, _ pubKey: SecKey, _ padding: SecPadding) -> Bool {
        var digest: Data = Data()
        switch padding {
        case .PKCS1SHA1:
            digest = sha1(data: Data())
        case .PKCS1SHA224:
            digest = sha224(data: Data())
        case .PKCS1SHA256:
            digest = sha256(data: Data())
        case .PKCS1SHA384:
            digest = sha384(data: Data())
        case .PKCS1SHA512:
            digest = sha512(data: Data())
        default:
            digest = sha1(data: Data())
        }
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        (digest as NSData).getBytes(&digestBytes, length: digest.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: signData.count)
        (signData as NSData).getBytes(&signatureBytes, length: signData.count)
        
        let status = SecKeyRawVerify(pubKey, padding, digestBytes, digestBytes.count, signatureBytes, signatureBytes.count)
        
        return status == errSecSuccess
    }
}
