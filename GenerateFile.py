import os

# Tentukan nama dan ukuran file sampel
file_name = 'file1MB.txt'
file_size_gb = 1

# Hitung ukuran dalam byte
file_size_bytes = file_size_gb * 1024 * 1024  # 1GB = 1024MB = 1024KB = 1024B

# Buat file sampel dengan ukuran yang ditentukan
with open(os.path.join("Sampel", file_name), 'w') as f:
    f.write(os.urandom(file_size_bytes))

print(f"File {file_name} telah dibuat dengan ukuran {file_size_gb} GB.")
