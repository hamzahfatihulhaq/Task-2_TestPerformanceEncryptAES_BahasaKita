from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import time
import psutil

sample_dir = 'Sampel'
result_dir = 'Hasil'
file_name = 'file1GB.bin'
# file_name = 'random_1mb.txt'
processes = ["AES_NotChunk", "AES_Chunk"]
KEY = get_random_bytes(32)

def AES_NotChunk(data, key):
    # print(type(data))
    # Encrypt
    start_time = time.time()
    e_cipher = AES.new(key, AES.MODE_EAX)
    nonce = e_cipher.nonce
    ciphertext, tag = e_cipher.encrypt_and_digest(data)
    # print(tag)

    # write file langsung 1GB 
    result_file = f'AES_NotChunk_Ciphertext.bin'
    with open(os.path.join(result_dir, result_file), 'wb') as result_f:
        result_f.write(ciphertext)

    encryption_time = time.time() - start_time
    
    # Mengukur penggunaan memori
    process = psutil.Process(os.getpid())
    memory_usage_encryption = process.memory_info().rss / (1024 ** 2)  # Dalam Megabytes

    # Decrypt
    start_time = time.time()
    d_cipher = AES.new(key, AES.MODE_EAX, nonce)

    with open(os.path.join(result_dir, result_file), 'rb') as f:
        ciphertext1 = f.read()

    d_data = d_cipher.decrypt(ciphertext1)
    # print(d_data)
    # print("tag: ",tag)
    try:
        d_cipher.verify(tag)
        # print("tag: ", d_cipher.verify(tag))
    except ValueError:
        print("Key incorrect or message corrupted")
    
    decryption_time = time.time() - start_time
    
    # Mengukur penggunaan memori
    process = psutil.Process(os.getpid())
    memory_usage_decryption = process.memory_info().rss / (1024 ** 2)  # Dalam Megabytes

    return encryption_time, decryption_time, memory_usage_encryption, memory_usage_decryption

def AES_Chunk(data, key):
    # Encrypt
    start_time = time.time()
    
    # Inisialisasi cipher dengan nonce
    encrypted_data = []
    for chunk in data:
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce

        ciphertext, tag = cipher.encrypt_and_digest(chunk)

        encrypted_data.append(nonce + ciphertext + tag)

    # write file dengan chunk 1kb 
    result_file = f'AES_Chunk_Ciphertext.bin'
    with open(os.path.join(result_dir, result_file), 'wb') as result_f:
        for chunk in encrypted_data:
            # print(len(chunk))
            result_f.write(chunk)

    
    encryption_time = time.time() - start_time

    # Mengukur penggunaan memori
    process = psutil.Process(os.getpid())
    memory_usage_encryption = process.memory_info().rss / (1024 ** 2)  # Dalam Megabytes

    # print("===============Dec")
    # Decrypt
    start_time = time.time()
    
    decrypted_data = []
    
    with open(os.path.join(result_dir, result_file), 'rb') as f:
        while True:
            chunk = f.read(16 + 1024*100 +16)  # Baca dalam chunk 1KB
            # print('enc',chunk)
            if not chunk:
                break
            nonce = chunk[:16]
            ciphertext = chunk[16:-16]
            tag = chunk[-16:]

            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

            decrypted_chunk = cipher.decrypt(ciphertext)

            try:
                cipher.verify(tag)
                decrypted_data.append(decrypted_chunk)
                # print("berhasil")
            except ValueError:
                print("Key incorrect or message corrupted")
    # print("===================")
    decryption_time = time.time() - start_time
    
    # Mengukur penggunaan memori
    process = psutil.Process(os.getpid())
    memory_usage_decryption = process.memory_info().rss / (1024 ** 2)  # Dalam Megabytes

    return encryption_time, decryption_time, memory_usage_encryption, memory_usage_decryption


def read_file_in_chunks(file_path, chunk_size=100*1024):
    chunks = []
    with open(file_path, 'rb') as file:
        while True:
            data_chunk = file.read(chunk_size)
            if not data_chunk:
                break
            chunks.append(data_chunk)
    return chunks

if __name__ == '__main__':
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)

    for process in processes:
        results = []
        file_chunks = read_file_in_chunks(os.path.join(sample_dir, file_name))
        
        if process == "AES_NotChunk": 
            print("AES Without Chunk")
            encryption_time, decryption_time, memory_usage_encryption, memory_usage_decryption = AES_NotChunk(b''.join(file_chunks), KEY)
        
        elif process == "AES_Chunk":
            print("AES With Chunk")
            encryption_time, decryption_time, memory_usage_encryption, memory_usage_decryption = AES_Chunk(file_chunks, KEY)

        result = {
            "File": file_name,
            "Process": process,
            "Encryption_Time": round(encryption_time, 6),
            "Decryption_Time": round(decryption_time, 6),
            "Memory_Usage_Enc": round(memory_usage_encryption, 2),
            "Memory_Usage_Dec": round(memory_usage_decryption, 2)
        }

        results.append(result)
         
    
        result_file = f'{process}_result.txt'
        with open(os.path.join(result_dir, result_file), 'w') as result_f:
            for result in results:
                result_f.write(f"File: {result['File']}, Process: {result['Process']}\n")
                result_f.write(f"Encryption Time: {result['Encryption_Time']} seconds\n")
                result_f.write(f"Decryption Time: {result['Decryption_Time']} seconds\n")
                result_f.write(f"Memory Usage Enc: {result['Memory_Usage_Enc']} MB\n")
                result_f.write(f"Memory Usage Dec: {result['Memory_Usage_Dec']} MB\n")
                result_f.write("---\n")
