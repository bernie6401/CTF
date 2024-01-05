import crypt   ## 导入 Linux 口令加密库
from tqdm import trange

def testPass(cryptPass):
    salt=cryptPass[cryptPass.find("$"):cryptPass.rfind("$")]  ## 获得盐值，包含 $id 部分
    # print(salt)
    dictFile=open('rockyou.txt','r', encoding='latin-1')
    for i in trange(14344392):
        try:
            word=dictFile.readline().strip("\n")
            # print(word)
            cryptWord=crypt.crypt(word,salt)                   ## 将密码字典中的值和盐值一起加密
            if (cryptWord==cryptPass):                           ## 判断加密后的数据和密码字段是否相等
                print ("[+]Found Password:"+word+"\n" )      ## 如果相等则打印出来
                return 
        except:
            print(f"[*] Wrong Decode Password happened at {i}")
    print ("[-] Password Not Found.\n")
    return 

def main():
    passFile=open('shadow.txt')
    for line in passFile.readlines():      ## 读取文件中的所有内容
        if ":" in line:
            user=line.split(":")[0]                     ## 获得用户名
            cryptPass=line.split(":")[1].strip(' ')     ## 获得密码字段
            print ("[*] Cracking Password for:"+user)
            testPass(cryptPass)
main()