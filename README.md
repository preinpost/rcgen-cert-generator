# 인증서 quinn 테스트

서버
```sh
cargo run --example server -- --cert server.crt --key server.key ./
```

클라이언트
```sh
cargo run --example client -- --ca server.der https://localhost:4433/README.md
```