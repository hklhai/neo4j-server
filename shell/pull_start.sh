#! /bin/sh
export PATH=/home/ubuntu1/.local/share/virtualenvs/srwc-NN3ejj4q/bin:$PATH:/usr/local/bin

#进入.py脚本所在目录
cd /home/ubuntu1/Project/srwc

git -c core.quotepath=false -c log.showSignature=false pull --progress --no-stat -v --progress origin master

cd webapi

nohup gunicorn -w 4 -b 127.0.0.1:8777 web:app web.log 2>&1 &
