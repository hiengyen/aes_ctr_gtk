# AES CTR Encrypt/Decrypt GUI GTK+

This is an AES encryption and decryption program in CTR (Counter Mode) with a graphical user interface using GTK+ 3. The program allows users to input data, encrypt, decrypt, and display results (plaintext, nonce, ciphertext) on the interface.

## Features
- Encrypt data input from the interface with 128-bit (32 HEX characters), 192-bit (48 HEX characters), or 256-bit (64 HEX characters) keys.
- Decrypt data from files containing `nonce` (8 bytes) and `ciphertext`.
- Display plaintext, nonce, and ciphertext in HEX format on the interface.
- Save encryption results to `encrypted.bin` file and decryption results to `decrypted.txt` file.
- Support simple interface with Encrypt, Decrypt, and Clear buttons.

## System Requirements
- **Linux**: GCC, GTK+ 3
- **Windows**: MinGW-w64, GTK+ 3

## Setting up Development Environment on Linux (Ubuntu/Debian)
```bash
### 1. Install compiler tools and GTK libraries

sudo apt update
sudo apt install build-essential libgtk-3-dev

### 2. Compile the program 
make

### 3. Run the program 
./aes_ctr_gtk

```

## Setting up Development Environment on Windows
### 1. Install MinGW-w64 and GTK+ 3
- **MinGW-w64**: Download and install MinGW-w64 from [MinGW-w64](https://www.mingw-w64.org/).
- **GTK+ 3**: Download GTK+ 3 from [MSYS2](https://www.msys2.org/). After installing MSYS2, open the MSYS2 terminal and run the following commands to install GTK+ 3:
  ```bash
  pacman -S mingw-w64-x86_64-gtk3
  ```

### 2. Configure Environment Variables
- Add the path to the GTK+ 3 `bin` directory (e.g., `C:\msys64\mingw64\bin`) to the `PATH` environment variable.

### 3. Compile the Program
- Open MSYS2 or MinGW-w64 terminal and navigate to the directory containing the source code.
- Run the following command to compile the program:
  ```bash
  make
  ```
  Or if not using Makefile, you can compile directly with the command:
  ```bash
  gcc -o aes_ctr_gtk aes_ctr_gtk.c aes.c -I<path_to_gtk_include> -L<path_to_gtk_lib> -lgtk-3 -lgobject-2.0 -lglib-2.0 -lgdk-3
  ```
  Replace `<path_to_gtk_include>` and `<path_to_gtk_lib>` with the corresponding paths to the `include` and `lib` directories of GTK+ 3.

### 4. Run the Program
- After successful compilation, run the program with the command:
  ```bash
  ./aes_ctr_gtk.exe
  ```

### Notes
- Ensure that all necessary GTK+ 3 libraries are in the `PATH` so the program can run without missing library errors.
