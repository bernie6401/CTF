# OS by sicc

:::danger
請愛惜共筆，勿進行惡意刪減
:::
:::info
上課前請先下載
1.[Virtual Box](https://www.virtualbox.org/)
2.[Linux](https://drive.google.com/file/d/1aOEkFmq95J0ryg_-oFjmJeyFw3jT9zdp/view?usp=sharing)
3.[簡報](https://slides.com/d/ckZ7Tm0/live)
4.虛擬機密碼：nisra
:::

:::warning
- 使用學校電腦的記得調整設定
    - 處理器建議降至2核心 
:::

## what is linux
- 一個開放原始碼的
- Unix-like
    - 類似Unix的作業系統
    - Unix
        - 多人多工
        - 分享電腦資源
- why linux?
	- linux 完全免費
	- 開放原始碼，有很多人共同維護，更新很快
	
## 基本概念
- shell
	- 接受指令的程式
	- 根據接受指令開啟程式、呼叫 syscall
- syscall
	- 系統提供的 function
	- 使用者對 shell 下指令
    - shell 透過 syscall 叫系統做事
- Filesystem
	- 根目錄為起始
    - 樹狀目錄
	- /
		- 根目錄
	- /bin
		- 系統必備執行檔
    - /home
        - 家目錄
        - 別稱：~
        - 成功登入後就直接在這裡了
	- /tmp
		- 放暫存檔
	- /boot
		- 核心目錄檔案
		- 跟開機有關的檔案
	- /usr
		- 系統程式資源
	- /var
		- 系統資訊、紀錄、暫存檔案

## 指令
- who
	- 查詢上線使用者
- whoami
    - 查詢現在使用者
- pwd
    - **p**rint **w**ork **d**irectory
	- 查看目前所在目錄
- ls
    - **l**i**s**t
    - 列出當前目錄內容
	- -a 列出所有目錄
    - -l 查看詳細目錄
	- 可使用 ls -al 列出所有檔案與詳細資料
- cd
    - 更換目錄 
    - **c**hange **d**irectory
    - \$ cd 路徑 (絕對或相對路徑)
    - \$ cd \. 回到目前資料夾
    - \$ cd \.\. 回到上一個資料夾
		- \.\. 可以重複使用
		- ex. cd \.\.\/\.\.\/\.\.\/otherdir
- cat
    - con**cat**enate
	- 用來引出檔案內容
- ./
    - 執行檔案
- clear
	- 清除畫面	
- mkdir
	- 創建一個空的目錄
	- mkdir 目錄名稱
- rmdir
	- 刪除**空**目錄
	- rmdir 目錄名稱
- touch
	- 新增空檔案
	- touch 檔案
- mv
	- 移動檔案/目錄
	- mv \[參數\]\<來源\>...\<目標\>
		- -i 詢問
		- -f 強制
- cp
	- 複製 檔案/目錄 到指定地點
	- cp -rf \<來源\>...\<目標\>
		- -r 遞迴
		- -f 強制
- rm
	- 刪除檔案或目錄 remove
	- rm \[參數\] 檔案（目錄）
		- -f 強制
		- -i 詢問
		- -r 遞迴（刪除目錄下所有東西）

## 權限
- sudo
    - 以 root 的權限執行指令
    - $ sudo <指令>
    - !!!需要輸入密碼!!!(但密碼不會顯示出來喔)
- chown
    - **ch**ange **own**er
    - 將檔案的所有權轉移給其他使用者
    - $ chown <使用者名稱> <檔案名稱>
- chmod
	- **ch**ange **mod**e
	- 變更檔案或目錄權限
	- chmod \<權限\>\<檔案（目錄）\>
- su
	- 切換成其他使用者
	- su \<username\>
	- `密碼也不會顯示喔`
### Lab 0x02

:::spoiler Solution ver.1

```bash=
sudo chown nisra:nisra /path/2/file
/path/2/file
```

:::

:::spoiler Solution ver.2

```bash=
su user # 密碼不會顯示
chmod 777 /path/to/file
/path/to/file
```

:::


## Package Manager
### apt
- **a**dvances **p**ackaging **t**ool
- 為 Debian 與其衍生的 Linux 套件管理器
- 有點像是 Android 的 play store 或是 ios 的 App store
	- **執行時需要最高權限（sudo）**
- sudo apt update 更新軟體庫清單
- sudo apt upgrade 升級系統軟體
- sudo apt install \<軟件名稱\> 安裝應用軟體

### vim
#### How to install
>sudo apt install vim 












---
###### tags: `Enlightened` `NISRA` `2022`

<style>
    .navbar-brand:before {
        content: ' NISRA × ';
        padding-left: 1.7em;
        background-image: url(https://i.imgur.com/ue2XHqP.png);
        background-repeat: no-repeat;
        background-size: contain;
    }
    .navbar-brand > .fa-file-text {
        padding-left: 0.1em;
        display: none;
    }
</style>
