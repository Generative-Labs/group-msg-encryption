#!/usr/bin/env bash

function waku(){
    echo "启动waku服务..."
    sudo nohup /home/ubuntu/waku/build/waku -tcp-port=60001 -key-file=nodekey -metrics-server=true -metrics-server-address=0.0.0.0 -ws=true -ws-port=60002 -filter=true -keep-alive=1 -lightpush=true -keep-alive=5 nohupcmd.out 2>&1 &
    echo "waku服务已启动..."
    sudo ps -ef | grep "waku"
    gotop-cjbassi
}

function web3mq(){
    echo "启动Web3MQ服务..."
    sudo nohup /home/ubuntu/web3mq/build/Web3MQ --config-file=config.toml -keep-alive=5 web3mq.out 2>&1 &
    echo "Web3MQ服务已启动..."
    sudo ps -ef | grep "Web3MQ"
    gotop-cjbassi
}

function init_server(){
    sudo snap install gotop-cjbassi
    sudo snap connect gotop-cjbassi:hardware-observe
    sudo snap connect gotop-cjbassi:mount-observe
    sudo snap connect gotop-cjbassi:system-observe



    echo "初始化Web3MQ服务..."
    sudo /home/ubuntu/web3mq/build/Web3MQ --generate-key /home/ubuntu/web3mq/nodekey
    sudo /home/ubuntu/web3mq/build/Web3MQ --migrate-db
    echo "Web3MQ服务初始化完成..."

    echo "初始化waku服务..."
    sudo /home/ubuntu/waku/build/waku --generate-key nodekey
    echo "waku服务初始化完成..."
}


function testing(){
    echo "请选择测试模式　[1:send  2:receive ]|　默认send模式"
    read mode
    case $mode in
    receive)
       echo "请 设置url:"
       read url
       if [ "$url" = "" ] ; then
           url="ws://54.202.94.88:23333/messages"
       fi
      /home/ubuntu/testing -c 100 -n 1 -u "$url" -k -v web3 -to user_2 -mod receive
      ;;
    1|*)
        echo "请 设置url:"
        read url
        if [ "$url" = "" ] ; then
           url="ws://34.222.218.123:23333/messages"
        fi
      /home/ubuntu/testing -c 100 -n 1 -u "$url" -k -v web3 -t=1 -to user_2
      ;;
    esac
}






case $1 in
web3mq)
  web3mq
  ;;
init|*)
  init_server
  source ./install_kernel.sh
  ;;
waku)
  waku
  ;;
test)
  testing
  ;;
esac