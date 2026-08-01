# 1000 Time Pad
A text editor with encryption support for securing your notes. Built using FLTK and C++. 

Features: 
- Encryption/decryption of text using AES-CBC supporting 128 bit, 192 bit, and 256 bit keys
- Salting and hashing of plaintext passwords using PBKDF2
- Supports all major keyboard shortcuts
- Changeable text size (zoom in/out)
- Smart find and replace
- Open recent files menu
- Toggleable word wrapping and line numbering 

To be added:
- Smart undo/redo algorithm
- Modern UI 

# About the encryption method
1000 Time Pad uses [AES-CBC](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (Advanced Encryption Standard, Cipher Block Chaining mode) to encrypt the contents of the text buffer. All three key sizes (128 bit, 192 bit, 256 bit) are supported. 
The user enters a password in plaintext, which is converted into an AES hex key of the desired key size using the [PBKDF2-SHA256](https://en.wikipedia.org/wiki/PBKDF2) algorithm to hash the password using a random salt. The text is then converted into a raw stream of bits, which are used to populate a sequence of 4x4 matrices. These matrices are taken as inputs to the AES algorithm. The resulting outputs are combined using CBC (Cipher Block Chaining, see e.g. [here](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)). 

# Building 
This project is a C++17 FLTK application built with MinGW-w64 (g++) and FLTK installed via vcpkg. 

Prerequisites:
- MinGW-w64 (providing g++, gdb) — e.g. installed at C:\mingw64
- vcpkg, with FLTK installed for the x64-mingw-dynamic triplet:
```vcpkg install fltk:x64-mingw-dynamic```

This project can be built by running the following command from the command line: 
```
g++ -g -std=c++17 `
  textencryptor.cpp AES.cpp PBKDF2.cpp `
  -o textencryptor.exe `
  -I "C:/vcpkg/installed/x64-mingw-dynamic/include" `
  -L "C:/vcpkg/installed/x64-mingw-dynamic/lib" `
  -lfltk -lgdi32 -lcomdlg32 -lole32 -luuid -lcomctl32
```
**Building with VS Code**

This project can also be built straight from VS Code using the included tasks.json file. Steps:
- Open the project folder in VS Code.
- Open the Run and Debug panel (Ctrl+Shift+D).
- From the dropdown at the top of that panel, select "Debug FLTK App".
- Press the green ▶ button (or F5).


# Project layout
```
├── textencryptor.cpp   # main application (window, menus, editor, dialogs)
├── AES.h / AES.cpp      # AES-128/192/256 implementation (CBC mode)
├── PBKDF2.h / PBKDF2.cpp # PBKDF2-HMAC-SHA256 password-to-key derivation
└── .vscode/
    ├── tasks.json        # build task
    └── launch.json        # debug launch configuration
```

# License 
This code is licensed under the MIT License. Please see the LICENSE file for more information. 
