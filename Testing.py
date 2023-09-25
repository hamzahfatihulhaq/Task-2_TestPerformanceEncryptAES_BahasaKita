from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import time
import psutil
import resource

sample_dir = 'Sampel'
result_dir = 'Hasil'
file_name = 'file1GB.bin'
# file_name = 'random_1mb.txt'
processes = [ "AES_Chunk", "AES_NotChunk"]
KEY = get_random_bytes(32)
BATCH_SIZE = int(1 * 1024 * 1024)

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

def AES_Chunk_AEX(data, key):
    # Encrypt
    start_time = time.time()
    
    # Inisialisasi cipher dengan nonce
    # write file dengan chunk 1kb 
    result_file = f'AES_Chunk_Ciphertext.bin'
    with open(os.path.join(result_dir, result_file), 'wb') as result_f:
        for chunk in data:
            cipher = AES.new(key, AES.MODE_EAX)
            nonce = cipher.nonce

            ciphertext, tag = cipher.encrypt_and_digest(chunk)

            # encrypted_data.append(nonce + ciphertext + tag)
            result_f.write(nonce + ciphertext + tag)

    
    encryption_time = time.time() - start_time

    # Mengukur penggunaan memori
    process = psutil.Process(os.getpid())
    memory_usage_encryption = process.memory_info().rss / (1024 ** 2)  # Dalam Megabytes

    # time.sleep(2)
    # Decrypt
    start_time = time.time()
    
    decrypted_data = []
    # resource.setrlimit(resource.RLIMIT_AS, (1 * 1024**3, resource.RLIM_INFINITY))
    
    with open(os.path.join(result_dir, result_file), 'rb') as f:
        while True:
            chunk = f.read(16 + BATCH_SIZE +16)  # Baca dalam chunk 1KB

            if not chunk:
                break

            # nonce = chunk[:16]
            # ciphertext = chunk[16:-16]
            # tag = chunk[-16:]

            cipher = AES.new(key, AES.MODE_EAX, nonce=chunk[:16])

            decrypted_chunk = cipher.decrypt(chunk[16:-16])

            try:
                cipher.verify(chunk[-16:])
                decrypted_data.append(decrypted_chunk)
                
            except ValueError:
                print("Key incorrect or message corrupted")

            del decrypted_chunk
 
    decryption_time = time.time() - start_time
    
    # Mengukur penggunaan memori
    process = psutil.Process(os.getpid())
    memory_usage_decryption = process.memory_info().rss / (1024 ** 2)  # Dalam Megabytes

    return encryption_time, decryption_time, memory_usage_encryption, memory_usage_decryption

# Menguji mode CTR atau CFB
def AES_Chunk(data, key):
    start_time = time.time()
    
    # Inisialisasi cipher dengan nonce
    result_file = f'AES_Chunk_Ciphertext.bin'
    with open(os.path.join(result_dir, result_file), 'wb') as result_f:
        cipher = AES.new(key, AES.MODE_CTR)  # Mode streaming seperti CFB
        
        for chunk in data:
            ciphertext = cipher.encrypt(chunk)
            result_f.write(ciphertext)
        
        result_f.flush()
    
    encryption_time = time.time() - start_time

    # Mengukur penggunaan memori
    process = psutil.Process(os.getpid())
    memory_usage_encryption = process.memory_info().rss / (1024 ** 2)  # Dalam Megabytes
    # time.sleep(2)

    # Decrypt
    start_time = time.time()
    
    decrypted_data = []
    with open(os.path.join(result_dir, result_file), 'rb') as f:
        cipher = AES.new(key, AES.MODE_CTR)  # Mode streaming seperti CFB
        
        while True:
            chunk = f.read(BATCH_SIZE)  # Baca dalam batch
            
            if not chunk:
                break
            
            decrypted_chunk = cipher.decrypt(chunk)
            decrypted_data.append(decrypted_chunk)

            del decrypted_chunk

    
    decryption_time = time.time() - start_time
    
    # Mengukur penggunaan memori
    process = psutil.Process(os.getpid())
    memory_usage_decryption = process.memory_info().rss / (1024 ** 2)  # Dalam Megabytes

    return encryption_time, decryption_time, memory_usage_encryption, memory_usage_decryption

def read_file_in_chunks(file_path):
    chunks = []
    with open(file_path, 'rb') as file:
        while True:
            data_chunk = file.read(BATCH_SIZE)
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
        
        if process == "AES_Chunk":
            print("AES With Chunk")
            encryption_time, decryption_time, memory_usage_encryption, memory_usage_decryption = AES_Chunk_AEX(file_chunks, KEY)

        # elif process == "AES_NotChunk": 
        #     print("AES Without Chunk")
        #     encryption_time, decryption_time, memory_usage_encryption, memory_usage_decryption = AES_NotChunk(b''.join(file_chunks), KEY)
        

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
