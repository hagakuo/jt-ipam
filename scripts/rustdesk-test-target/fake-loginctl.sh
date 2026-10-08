#!/bin/sh
# 測試靶用的假 loginctl：容器裡沒有 systemd-logind。受控端靠 loginctl 找「seat0 上目前登入的使用者」；
# 找不到時它拿空字串去查 `getent passwd`，結果列出全部帳號（nobody 的 shell 是 nologin）→ 誤以為還在登入畫面，
# 永遠不啟動連線管理程式（--cm），檔案傳輸的列目錄、上傳下載都沒有人處理（2026-10-05 驗附錄 J 時查到）。
# 這裡回報：root 在 seat0 上有一個作用中的 X11 工作階段（DISPLAY=:0）。
case "$1" in
    ""|list-sessions)
        echo "SESSION  UID USER SEAT  TTY"
        echo "      1    0 root seat0 tty7"
        echo ""
        echo "1 sessions listed."
        ;;
    show-session)
        shift
        prop=""
        while [ $# -gt 0 ]; do
            case "$1" in
                -p) prop="$2"; shift 2 ;;
                --value) shift ;;
                *) shift ;;
            esac
        done
        case "$prop" in
            State) echo "State=active" ;;
            Active) echo "Active=yes" ;;
            Type) echo "Type=x11" ;;
            Display) echo "Display=:0" ;;
            Name) echo "Name=root" ;;
            User) echo "User=0" ;;
            Remote) echo "Remote=no" ;;
            Class) echo "Class=user" ;;
            Seat) echo "Seat=seat0" ;;
            LockedHint) echo "LockedHint=no" ;;
            Leader) echo "Leader=1" ;;
            "") printf 'Id=1\nUser=0\nName=root\nSeat=seat0\nDisplay=:0\nType=x11\nClass=user\nActive=yes\nState=active\nRemote=no\n' ;;
            *) echo "${prop}=" ;;
        esac
        ;;
    *) ;;
esac
exit 0
