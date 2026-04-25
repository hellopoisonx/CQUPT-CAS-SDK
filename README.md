# CQUPT-CAS-SDK

> 重庆邮电大学 统一身份认证平台 SDK

> 本项目是 *Auto CQUPT Plan* 的一部分

> [!warning]
> 
> 本项目仅供学习，请勿用于非法用途，否则后果自负！！！

![images](./images/cover.png)

### 1. 项目简介

`CQUPT CAS SDK` 是由 `Golang` 编写的 **重庆邮电大学统一身份认证中心SDK**，实现了**登录**功能。

### 2. 使用方法

**单元测试文件：**

```go
package amin

import "testing"

func Test_Login(t *testing.T) {
    // 获取SDK实例
    sdk := GetSDK("username", "password")

    // 执行登录
    loc, err := sdk.Login("http://jwzx.cqupt.edu.cn/tysfrz/navication.php?id=user")

    if err != nil {
        t.Errorf("Error: %v", err.Error())
    }

    t.Logf("Location: %v", loc)
}
```

**输出：**

```shell
go test -v
=== RUN   Test_Login
    sdk_test.go:16: Location: http://jwzx.cqupt.edu.cn/tysfrz/navication.php?id=user&ticket=ST-1088667-4ObMbxr-xxxxxxxxxxxx-xxxxauthserver2
--- PASS: Test_Login (0.35s)
PASS
ok      github.com/Auto-CQUPT-Plan/CQUPT-CAS-SDK    0.359s
```

**参数说明：**

| 参数       | 说明        |
| -------- | --------- |
| username | 用户账号      |
| password | 密码        |
| service  | 要登陆服务的URL |

### 3. 认证流程

#### 3.1 获取 `JssID` 和 `router` 两个Cookie

```go
func (r *HttpSpyderCore) GetGlobalCookie() error {
    finalURL := fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService)

    req, err := http.NewRequest("GET", finalURL, nil)
    if err != nil {
        return err
    }

    for key, val := range r.headers {
        req.Header.Set(key, val)
    }

    resp, err := r.client.Do(req)
    if err != nil {
        return err
    }

    var cookies []string
    for _, cookieHeader := range resp.Header["Set-Cookie"] {
        if idx := strings.Index(cookieHeader, ";"); idx != -1 {
            cookieHeader = cookieHeader[:idx]
        }
        // 去除可能的空格
        cookieHeader = strings.TrimSpace(cookieHeader)
        if cookieHeader != "" {
            cookies = append(cookies, cookieHeader)
        }
    }

    r.cookies = strings.Join(cookies, "; ")
    r.headers["Cookie"] = r.cookies

    _ = resp.Body.Close()

    return nil
}
```

#### 3.2 获取 `pwdEncryptSalt` 和 `execution` 两个参数

- 获取源码

```go
func (r *HttpSpyderCore) GetBasicData() (*BasicData, error) {
    data := &BasicData{}

    finalURL := fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService)

    req, err := http.NewRequest("GET", finalURL, nil)
    if err != nil {
        return nil, err
    }

    for key, val := range r.headers {
        req.Header.Set(key, val)
    }

    resp, err := r.client.Do(req)
    if err != nil {
        return nil, err
    }

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    data.Execution = extractor.ExtractInputValue(bodyBytes, `id="execution"`, `name="execution"`)
    data.PwdEncryptSalt = extractor.ExtractInputValue(bodyBytes, `id="pwdEncryptSalt"`)

    _ = resp.Body.Close()

    return data, nil
}
```

- 正则匹配

```go
func ExtractInputValue(html []byte, attrs ...string) string {
    htmlStr := string(html)

    inputPattern := `<input[^>]+`
    for _, attr := range attrs {
        inputPattern += `[^>]*` + attr + `[^>]*`
    }
    inputPattern += `[^>]*>`

    re := regexp.MustCompile(`(?i)` + inputPattern)
    match := re.FindString(htmlStr)
    if match == "" {
        return ""
    }

    valueRe := regexp.MustCompile(`(?i)value\s*=\s*["']([^"']*)["']`)
    valueMatch := valueRe.FindStringSubmatch(match)
    if len(valueMatch) > 1 {
        return valueMatch[1]
    }

    return ""
}
```

#### 3.3 用 `pwdEncryptSalt` 加密 `password`

```go
var aesChars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

func randomStringGo(length int) (string, error) {
    result := make([]byte, length)
    charsLen := big.NewInt(int64(len(aesChars)))
    for i := 0; i < length; i++ {
        num, err := rand.Int(rand.Reader, charsLen)
        if err != nil {
            return "", err
        }
        result[i] = aesChars[num.Int64()]
    }
    return string(result), nil
}

func pkcs7Padding(data []byte, blockSize int) []byte {
    padding := blockSize - len(data)%blockSize
    padtext := make([]byte, padding)
    for i := range padtext {
        padtext[i] = byte(padding)
    }
    return append(data, padtext...)
}

func aesEncryptGo(plaintext, key, iv []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(iv) != block.BlockSize() {
        return nil, errors.New("invalid iv size")
    }

    plaintext = pkcs7Padding(plaintext, block.BlockSize())
    ciphertext := make([]byte, len(plaintext))
    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext, plaintext)

    return ciphertext, nil
}

func EncryptPasssword(password, salt string) (string, error) {
    randomStr, err := randomStringGo(64)
    if err != nil {
        return "", fmt.Errorf("random error: %w", err)
    }

    passwordStr := randomStr + password

    key := []byte(strings.TrimSpace(salt))
    if len(key) < 16 {
        key = append(key, make([]byte, 16-len(key))...)
    } else if len(key) > 16 {
        key = key[:16]
    }

    iv, err := randomStringGo(16)
    if err != nil {
        return "", fmt.Errorf("gen IV fail: %w", err)
    }

    encrypted, err := aesEncryptGo([]byte(passwordStr), key, []byte(iv))
    if err != nil {
        return "", fmt.Errorf("AES encrypt fail: %w", err)
    }

    encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)

    encryptedURL := url.QueryEscape(encryptedBase64)

    return encryptedURL, nil
}
```

#### 3.4 执行登陆动作

```go
func (r *HttpSpyderCore) GetLocation(body *strings.Reader) (string, error) {
    finalURL := fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService)

    req, err := http.NewRequest("POST", finalURL, body)
    if err != nil {
        return "", err
    }

    for key, val := range r.headers {
        req.Header.Set(key, val)
    }

    resp, err := r.client.Do(req)
    if err != nil {
        return "", err
    }

    _ = resp.Body.Close()

    for key, val := range resp.Header {
        if key == "Location" {
            return val[0], nil
        }
    }

    return "", nil
}
```
