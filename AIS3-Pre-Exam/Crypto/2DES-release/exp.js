const crypto = require('crypto')
const assert = require('assert')


const hint_pt = Buffer.from('AIS3{??????????}', 'utf8')
let hint = '118cd68957ac93b269335416afda70e6d79ad65a09b0c0c6c50917e0cee18c93'
const iv = Buffer.concat([Buffer.from('AIS3 三')])
console.log(iv)

function encrypt(msg, key, iv) {
    const cipher = crypto.createCipheriv('des-cbc', key, iv)
    let encrypted = cipher.update(msg)
    encrypted = Buffer.concat([encrypted, cipher.final()])
    return encrypted
}

function decrypt(msg, key, iv) {
    const decipher = crypto.createDecipheriv('des-cbc', key, iv)
    let decrypted = decipher.update(msg, 'nyan~')
    decrypted = Buffer.concat([decrypted, decipher.final()])
    return decrypted
}

function intToHexStr(num) {
    var hexString = '';
    for (var i = 0; i < 8; i++) {
      var byte = num & 0xff; // 获取低8位
      var hex = byte.toString(16).padStart(2, '0'); // 转换为两位的十六进制字符串
      hexString = hex + hexString; // 将转换后的字符串拼接到结果中
      num = num >> 8; // 右移8位，处理下一个字节
    }
    return hexString;
}

var key1_table = []
var key2_table = []
var key1 = key2 = Buffer.from(intToHexStr(256), 'hex')

for (let idx = 0; idx < 2**32; idx++)
{
    tmp = encrypt(hint_pt, key1, iv)
    key1_table.push(tmp)
    key2_table.push(decrypt(hint, key2, iv))

    var key1 = key2 = Buffer.from(intToHexStr(idx + 1), 'hex')
}

for (let i = 0; i < 2**32; i++)
{
    for (let j = 0; j < 2**32; j++)
    {
        if (key1_table[i] == key2_table[j])
        {
            console.log("key1 = ", i, "\nkey2 = ", j)
            break
        }
    }
}