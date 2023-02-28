#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
file_name=1000
for next in ${file_name}.tar
while [ $file_name > 1 ]
    do
        echo "Untaring - $file_name"
        tar -xvf ${file_name}.tar #-C ./
        file_name=$(($file_name-1))
        mkdir ./$file_name
        mv ${file_name}.tar ./$file_name
        cd ./${file_name}
    done
file_name=$(($file_name-1))
while [ "$file_name" > "0" ]
    do
        cd ./${file_name}
        file_name=$(($file_name-1))
        if [ "$file_name" == "0" ]
            then ls -al
            cat filler.txt
            mv flag.png ~/CTF/PicoCTF/Misc/like1000
        fi
    done
exit 0