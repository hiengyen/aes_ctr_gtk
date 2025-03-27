# AES CTR Encrypt/Decrypt GUI GTK3 

Đây là một chương trình mã hóa và giải mã AES trong chế độ CTR (Counter Mode) với giao diện đồ họa sử dụng GTK+ 3 trên Linux. Chương trình hiển thị plaintext, ciphertext và nonce để mục đích demo.

## Tính năng
- Mã hóa dữ liệu nhập từ giao diện với khóa 128-bit (32 ký tự HEX).
- Giải mã dữ liệu từ file chứa `nonce` và `ciphertext`.
- Hiển thị plaintext, ciphertext, và nonce trên giao diện (demo).
- Lưu kết quả mã hóa vào `encrypted.bin` và giải mã vào `decrypted.txt`.

## Yêu cầu hệ thống
- **Linux**: GCC, GTK+ 3

## Thiết lập môi trường lập trình trên Linux (Ubuntu/Debian)

### 1. Cài đặt công cụ biên dịch và thư viện GTK
```bash
sudo apt update
sudo apt install build-essential libgtk-3-dev

### 2. Biên dịch chương trình 
make

### 3. Chạy chương trình 
./aes_ctr_gtk

