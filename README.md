## zixc rust开发环境

- 适用于zxic的设备 比如u10l/mf936 
- 构建rust程序，无需buildroot
- 使用musl构建静态链接的binary 


## 使用构建方法

```sh
nix develop .#zxic --extra-experimental-features "nix-command flakes"
cargo build --release  --target=armv7-unknown-linux-musleabi
```

运行方式
```sh
adb push ./target/armv7-unknown-linux-musleabi/release/zxic_ping /etc_rw/zxic_ping
/etc_rw/zxic_ping 192.168.0.1:80
```


### 相关项目
- https://github.com/anysoft/zxic-web-tty
- https://github.com/Amamiyashi0n/alice-pusher-bot-zxic.git