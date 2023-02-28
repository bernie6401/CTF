#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
file_name=999

while [ "$file_name" > "1" ]
    do
        cd ./${file_name}
        file_name=$(($file_name-1))
        if [ "$file_name" == "5" ]
        then
            break
        fi
    done

while [ $file_name -le 999 ]
    do
        echo $file_name
        file_name=$(($file_name+1))
        mv ./* /mnt/d/Download/Trash
        cd ../
    done
exit 0