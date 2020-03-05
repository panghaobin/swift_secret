//
//  ViewController.swift
//  swift_secret
//
//  Created by 张三 on 2020/3/3.
//  Copyright © 2020 phbtttttt@gmail.com. All rights reserved.
//

import UIKit
import Security
import CommonCrypto

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
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
        
    }

    
}

