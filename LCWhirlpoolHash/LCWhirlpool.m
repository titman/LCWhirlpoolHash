//
//
//      _|          _|_|_|
//      _|        _|
//      _|        _|
//      _|        _|
//      _|_|_|_|    _|_|_|
//
//
//  Copyright (c) 2014-2015, Licheng Guo. ( http://nsobject.me )
//  http://github.com/titman
//
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//  IN THE SOFTWARE.
//

#import <UIKit/UIKit.h>
#import "LCWhirlpool.h"
#import <CommonCrypto/CommonCryptor.h>

@interface LCWhirlpool () <UIWebViewDelegate>

@property (nonatomic, strong) UIWebView * web;

@property (nonatomic, copy) LCWhirlpoolCompletion completion;
@property (nonatomic, copy) NSString * string;

@property BOOL loaded;

@end

@implementation LCWhirlpool

+(LCWhirlpool *) share
{
    static LCWhirlpool * _whirlpool = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        
        _whirlpool = [[LCWhirlpool alloc] init];
        
    });
    
    return _whirlpool;
}

-(instancetype) init
{
    if (self = [super init]) {
        
        self.web = [[UIWebView alloc] init];
        self.web.delegate = self;
        
        NSString * source = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"LCHASH" ofType:nil] encoding:NSUTF8StringEncoding error:nil];

        [self.web loadHTMLString:[self AES128Decrypt:source] baseURL:nil];
    }
    
    return self;
}

-(void) whirlpoolWithString:(NSString *)string completion:(LCWhirlpoolCompletion)completion
{
    if (!string || string.length <= 0) {
        
        NSError * error = [[NSError alloc] initWithDomain:@"Invalid String" code:1 userInfo:nil];
        
        completion(error, nil);
    }
    
    self.string = string;
    self.completion = completion;
    
    if (self.loaded) {
        
        [self execute];
    }
}

-(void) execute
{
    if (self.completion && self.string.length) {
        
        NSString * resut = [self.web stringByEvaluatingJavaScriptFromString:[NSString stringWithFormat:@"LCHASH(\"%@\")", self.string]];
        
        self.completion(resut.length ? nil : [[NSError alloc] initWithDomain:@"An error occurred" code:1 userInfo:nil], resut);
    }
}

#pragma mark -

- (void)webViewDidFinishLoad:(UIWebView *)webView
{
    self.loaded = YES;
    
    [self execute];
}

#pragma mark - 

#define AES_KEY	  @"FF1A927b2b9D402C"
#define AES_IV    @"K33CFa97E000220b"

-(NSString *) AES128Decrypt:(NSString *)encryptText
{
    NSMutableData * data = [NSMutableData data];
    unsigned char whole_byte;
    
    char byte_chars[3] = {'\0','\0','\0'};
    
    int i;
    for (i=0; i < [encryptText length] / 2; i++) {
        byte_chars[0] = [encryptText characterAtIndex:i*2];
        byte_chars[1] = [encryptText characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          [AES_KEY UTF8String],
                                          kCCBlockSizeAES128,
                                          [AES_IV UTF8String],
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    
    if (cryptStatus == kCCSuccess) {
        
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    
    free(buffer);
    return nil;
}


@end
