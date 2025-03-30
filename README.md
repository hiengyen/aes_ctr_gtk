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


## Thiết lập môi trường lập trình trên Windows
### 1. Cài đặt MinGW-w64 và GTK+ 3
- **MinGW-w64**: Tải và cài đặt MinGW-w64 từ [MinGW-w64](https://www.mingw-w64.org/).
- **GTK+ 3**: Tải GTK+ 3 từ [MSYS2](https://www.msys2.org/). Sau khi cài đặt MSYS2, mở terminal MSYS2 và chạy các lệnh sau để cài đặt GTK+ 3:
  ```bash
  pacman -S mingw-w64-x86_64-gtk3
  ```

### 2. Cấu hình biến môi trường
- Thêm đường dẫn đến thư mục `bin` của GTK+ 3 (ví dụ: `C:\msys64\mingw64\bin`) vào biến môi trường `PATH`.

### 3. Biên dịch chương trình
- Mở terminal MSYS2 hoặc MinGW-w64 và chuyển đến thư mục chứa mã nguồn.
- Chạy lệnh sau để biên dịch chương trình:
  ```bash
  make
  ```
  Hoặc nếu không sử dụng Makefile, bạn có thể biên dịch trực tiếp bằng lệnh:
  ```bash
  gcc -o aes_ctr_gtk aes_ctr_gtk.c aes.c -I<path_to_gtk_include> -L<path_to_gtk_lib> -lgtk-3 -lgobject-2.0 -lglib-2.0 -lgdk-3
  ```
  Thay `<path_to_gtk_include>` và `<path_to_gtk_lib>` bằng đường dẫn tương ứng đến thư mục `include` và `lib` của GTK+ 3.

### 4. Chạy chương trình
- Sau khi biên dịch thành công, chạy chương trình bằng lệnh:
  ```bash
  ./aes_ctr_gtk.exe
  ```

### Lưu ý
- Đảm bảo rằng tất cả các thư viện cần thiết của GTK+ 3 có trong `PATH` để chương trình có thể chạy mà không gặp lỗi thiếu thư viện.
