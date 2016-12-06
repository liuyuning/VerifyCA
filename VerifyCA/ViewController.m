//
//  ViewController.m
//  VerifyCA
//
//  Created by liuyuning on 2016/12/1.
//  Copyright © 2016年 liuyuning. All rights reserved.
//

#import "ViewController.h"
#import <CommonCrypto/CommonCrypto.h>

#import <openssl/pem.h>
#import <openssl/err.h>
#import "asn1_locl.h"

#define USE_CC_SHA 0

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    [self testManualVerify];
    [self testOpenSSLVerify];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

//RSA pub dec
- (NSData *)OpenSSL_RSA_DecryptData:(NSData *)cipherData withPublicKey:(RSA *)rsaKey{
    NSMutableData *plainData = [NSMutableData data];
    if (rsaKey) {
        int block_size = RSA_size(rsaKey);
        uint8_t *buffer = malloc(block_size);
        
        if (buffer) {
            for (int i = 0; i < cipherData.length / block_size; i++) {
                
                int out_len = RSA_public_decrypt(block_size, (uint8_t *)cipherData.bytes + block_size * i, buffer, rsaKey, RSA_PKCS1_PADDING);
                if (out_len > 0) {
                    [plainData appendBytes:buffer length:out_len];
                }
                else{
                    NSLog(@"RSA_private_decrypt error:%d",out_len);
                    plainData = nil;
                    break;
                }
            }
            free(buffer);
        }
    }
    return plainData.length ? plainData : nil;
}

//Certificate without signature info
- (NSData *)certInfoOfCertificate:(NSData *)certData{
    NSData *data = nil;
    const unsigned char *pp = certData.bytes;
    X509 *cert = d2i_X509(NULL, &pp, certData.length);
    if (cert) {
        unsigned char *buff = NULL;
        int len = i2d_X509_CINF((cert)->cert_info, &buff);
        //int len = ASN1_item_i2d((ASN1_VALUE *)cert->cert_info, &buff, ASN1_ITEM_rptr(X509_CINF));
        if (buff) {
            data = [NSData dataWithBytes:buff length:len];
            OPENSSL_free(buff);
        }
        X509_free(cert);
    }
    return data;
}

//Signature data
- (NSData *)certSignOfCertificate:(NSData *)certData{
    NSData *data = nil;
    const unsigned char *pp = certData.bytes;
    X509 *cert = d2i_X509(NULL, &pp, certData.length);
    if (cert) {
        data = [NSData dataWithBytes:cert->signature->data length:cert->signature->length];
        X509_free(cert);
    }
    return data;
}


//证书验证过程：见图Google Internet Authority G2.png
//所需数据：原文、签名值、公钥（原文和签名值都在同一个证书里，如图；公钥是指签发者Issuer的公钥，即上一级证书里的公钥，如果是根证书那就是自己的公钥）
//1、将原文[Cert info]做哈希计算，得Hash1
//2、将签名值[Signature data]用上级公钥解密，得Hash2
//3、将Hash1和Hash2对比是否一致

//证书包含3部分内容：
//1、证书信息，包括名称、签发者、日期、加密算法之类
//2、公钥，用来对数据进行加密
//3、签名，是上级证书签发机构对“证书信息”和“公钥”哈希之后再用私钥加密的内容，用来验证1和2的正确性

//证书的相关信息可以使用命令查看：openssl x509 -in 'Google Internet Authority G2.cer' -inform DER -text -noout

- (void)testManualVerify{
    
    NSString *rootPath = [[NSBundle mainBundle] pathForResource:@"GeoTrust Global CA.cer" ofType:nil];
    NSString *g2Path = [[NSBundle mainBundle] pathForResource:@"Google Internet Authority G2.cer" ofType:nil];
    
    NSData *rootCertData = [NSData dataWithContentsOfFile:rootPath];
    NSData *g2CertData = [NSData dataWithContentsOfFile:g2Path];
    
    NSData *certInfo = [self certInfoOfCertificate:g2CertData];
    NSData *certSign = [self certSignOfCertificate:g2CertData];
    
    NSString *certInfoPath = [NSHomeDirectory() stringByAppendingString:@"/Documents/GoogleG2_CertInfo.dat"];
    NSString *certSignPath = [NSHomeDirectory() stringByAppendingString:@"/Documents/GoogleG2_SignData.dat"];
    
    [certInfo writeToFile:certInfoPath atomically:YES];
    [certSign writeToFile:certSignPath atomically:YES];
    
#if USE_CC_SHA
    unsigned char shaOut[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(certInfo.bytes, (CC_LONG)certInfo.length, (unsigned char *)&shaOut);
    NSData *certInfoHash = [NSData dataWithBytes:shaOut length:CC_SHA256_DIGEST_LENGTH];
    NSLog(@"[HASH]:%@",certInfoHash);//[HASH]:<0e0532dc a6d8bce0 5cc9286d e0789a86 5bba034d 98cd66cf 0cc30854 67eb5cb0>
#else
    unsigned char shaOut[SHA256_DIGEST_LENGTH] = {0};
    SHA256(certInfo.bytes, certInfo.length, shaOut);
    NSData *certInfoHash = [NSData dataWithBytes:shaOut length:SHA256_DIGEST_LENGTH];
    NSLog(@"[HASH]:%@",certInfoHash);//[HASH]:<0e0532dc a6d8bce0 5cc9286d e0789a86 5bba034d 98cd66cf 0cc30854 67eb5cb0>
#endif
    
    const unsigned char *ppRoot = rootCertData.bytes;
    X509 *certRoot = d2i_X509(NULL, &ppRoot, rootCertData.length);
    if (certRoot) {
        EVP_PKEY *pub_key = X509_get_pubkey(certRoot);
        if(pub_key){
            NSData *signatureData = certSign;
            NSData *decryptData = [self OpenSSL_RSA_DecryptData:signatureData withPublicKey:pub_key->pkey.rsa];
            NSLog(@"[DEC]:%@",decryptData);//[DEC]:<3031300d 06096086 48016503 04020105 0004200e 0532dca6 d8bce05c c9286de0 789a865b ba034d98 cd66cf0c c3085467 eb5cb0>
            
            const unsigned char *p = decryptData.bytes;
            X509_SIG *sig = d2i_X509_SIG(NULL, &p, (long)decryptData.length);
            if (sig) {
                NSLog(@"[DGST]:%@",[NSData dataWithBytes:sig->digest->data length:sig->digest->length]);
                
                if (0 == memcmp(shaOut, sig->digest->data, sig->digest->length)) {
                    NSLog(@"Manual verify signature is valid");
                }
                X509_SIG_free(sig);
            }
            EVP_PKEY_free(pub_key);
        }
        X509_free(certRoot);
    }
}

//int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
//https://www.openssl.org/docs/manmaster/man3/X509_verify.html
- (void)testOpenSSLVerify{
    NSString *rootPath = [[NSBundle mainBundle] pathForResource:@"GeoTrust Global CA.cer" ofType:nil];
    NSString *g2Path = [[NSBundle mainBundle] pathForResource:@"Google Internet Authority G2.cer" ofType:nil];
    
    NSData *rootCertData = [NSData dataWithContentsOfFile:rootPath];
    NSData *g2CertData = [NSData dataWithContentsOfFile:g2Path];
    
    OpenSSL_add_all_algorithms();
    //ERR_load_BIO_strings();
    //ERR_load_crypto_strings();
    
    const unsigned char *ppG2 = g2CertData.bytes;
    X509 *certG2 = d2i_X509(NULL, &ppG2, g2CertData.length);
    if (certG2) {
        
        //const unsigned char *ppPubKey = pubKeyData.bytes;
        //EVP_PKEY *pub_key = d2i_PUBKEY(NULL, &ppPubKey, pubKeyData.length);
        const unsigned char *ppRoot = rootCertData.bytes;
        X509 *certRoot = d2i_X509(NULL, &ppRoot, rootCertData.length);
        if (certRoot) {
            EVP_PKEY *pub_key = X509_get_pubkey(certRoot);
            
            if (pub_key) {
                
                //X509_verify() -> ASN1_item_verify() -> EVP_DigestVerifyFinal() -> EVP_DigestFinal_ex(), EVP_PKEY_verify() -> pkey_rsa_verify() -> RSA_verify() -> int_rsa_verify() -> RSA_public_decrypt, d2i_X509_SIG()
                int verify = X509_verify(certG2, pub_key);
                NSLog(@"X509_verify:%d",verify);
                
                if (verify) {
                    NSLog(@"Signature is valid");
                }
                else{
                    NSLog(@"%lu",ERR_get_error());
                    NSLog(@"%s",ERR_error_string(ERR_get_error(), NULL));
                }
                
                //Test call ASN1_item_verify()
                verify = ASN1_item_verify_(ASN1_ITEM_rptr(X509_CINF), certG2->sig_alg, certG2->signature, certG2->cert_info, pub_key);
                NSLog(@"ASN1_item_verify_:%d",verify);
                
                EVP_PKEY_free(pub_key);
            }
            X509_free(certRoot);
        }
        
        X509_free(certG2);
    }
}

//Source code of ASN1_item_verify()
int ASN1_item_verify_(const ASN1_ITEM *it, X509_ALGOR *a, ASN1_BIT_STRING *signature, void *asn, EVP_PKEY *pkey)
{
    EVP_MD_CTX ctx;
    unsigned char *buf_in = NULL;
    int ret = -1, inl;
    
    int mdnid, pknid;
    
    if (!pkey) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }
    
    if (signature->type == V_ASN1_BIT_STRING && signature->flags & 0x7) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
        return -1;
    }
    
    EVP_MD_CTX_init(&ctx);
    
    /* Convert signature OID into digest and public key OIDs */
    if (!OBJ_find_sigid_algs(OBJ_obj2nid(a->algorithm), &mdnid, &pknid)) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
        goto err;
    }
    if (mdnid == NID_undef) {
        if (!pkey->ameth || !pkey->ameth->item_verify) {
            ASN1err(ASN1_F_ASN1_ITEM_VERIFY,
                    ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
            goto err;
        }
        ret = pkey->ameth->item_verify(&ctx, it, asn, a, signature, pkey);
        /*
         * Return value of 2 means carry on, anything else means we exit
         * straight away: either a fatal error of the underlying verification
         * routine handles all verification.
         */
        if (ret != 2)
            goto err;
        ret = -1;
    } else {
        const EVP_MD *type;
        type = EVP_get_digestbynid(mdnid);
        if (type == NULL) {
            ASN1err(ASN1_F_ASN1_ITEM_VERIFY,
                    ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
            goto err;
        }
        
        /* Check public key OID matches public key type */
        if (EVP_PKEY_type(pknid) != pkey->ameth->pkey_id) {
            ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ASN1_R_WRONG_PUBLIC_KEY_TYPE);
            goto err;
        }
        
        if (!EVP_DigestVerifyInit(&ctx, NULL, type, NULL, pkey)) {
            ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_EVP_LIB);
            ret = 0;
            goto err;
        }
        
    }
    
    inl = ASN1_item_i2d(asn, &buf_in, it);
    
    if (buf_in == NULL) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    if (!EVP_DigestVerifyUpdate(&ctx, buf_in, inl)) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_EVP_LIB);
        ret = 0;
        goto err;
    }
    
    OPENSSL_cleanse(buf_in, (unsigned int)inl);
    OPENSSL_free(buf_in);
    
    if (EVP_DigestVerifyFinal(&ctx, signature->data,
                              (size_t)signature->length) <= 0) {
        ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_EVP_LIB);
        ret = 0;
        goto err;
    }
    /*
     * we don't need to zero the 'ctx' because we just checked public
     * information
     */
    /* memset(&ctx,0,sizeof(ctx)); */
    ret = 1;
err:
    EVP_MD_CTX_cleanup(&ctx);
    return (ret);
}

@end
