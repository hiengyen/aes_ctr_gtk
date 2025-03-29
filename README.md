# AES CTR Encrypt/Decrypt GUI GTK+

Đây là một chương trình mã hóa và giải mã AES trong chế độ CTR (Counter Mode) với giao diện đồ họa sử dụng GTK+ 3. Chương trình cho phép người dùng nhập dữ liệu, mã hóa, giải mã và hiển thị kết quả (plaintext, nonce, ciphertext) trên giao diện.

## Tính năng
- Mã hóa dữ liệu nhập từ giao diện với khóa 128-bit (32 ký tự HEX), 192-bit (48 ký tự HEX), hoặc 256-bit (64 ký tự HEX).
- Giải mã dữ liệu từ file chứa `nonce` (8 byte) và `ciphertext`.
- Hiển thị plaintext, nonce, và ciphertext dưới dạng HEX trên giao diện.
- Lưu kết quả mã hóa vào file `encrypted.bin` và kết quả giải mã vào file `decrypted.txt`.
- Hỗ trợ giao diện đơn giản với các nút Encrypt, Decrypt, và Clear.

## Yêu cầu hệ thống
- **Linux**: GCC, GTK+ 3
- **Windows**: MinGW-w64, GTK+ 3

## Thiết lập môi trường lập trình trên Linux (Ubuntu/Debian)
```bash
### 1. Cài đặt công cụ biên dịch và thư viện GTK

sudo apt update
sudo apt install build-essential libgtk-3-dev

### 2. Biên dịch chương trình 
make

### 3. Chạy chương trình 
./aes_ctr_gtk
```
```
