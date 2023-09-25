import random
import string

# Fungsi untuk menghasilkan string acak
def generate_random_string(size):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(size))

# Ukuran file dalam byte (1MB)
file_size = 1024 * 1024

# Generate string acak sekitar 1MB
random_string = generate_random_string(file_size)

# Simpan string ke dalam file teks
file_path = "Sampel/random_1mb.txt"
with open(file_path, "w") as file:
    file.write(random_string)

print(f"File '{file_path}' telah dibuat dengan ukuran sekitar 1MB.")
