import concurrent
import os
import struct
from tqdm import tqdm
from PIL import Image
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from Crypto.Random import get_random_bytes
from concurrent.futures import ThreadPoolExecutor

class Encrypt():

    def __init__(self,model,input_folder,output_folder_encrypt,output_folder_decrypt,video_key = None,image_key=None):
        """初始化方法"""
        if video_key==None and image_key==None:
            image_file_name = 'image_key.txt'
            video_file_name = 'video_key.txt'
            if os.path.isfile(image_file_name) and os.path.isfile(video_file_name) and\
                    self.file_has_content(image_file_name) and self.file_has_content(video_file_name):
                video_key = self.read_file_to_key('video','video_key.txt')
                image_key = self.read_file_to_key('image','image_key.txt')
            else:
                video_key = self.generate_video_key()
                image_key = self.generate_image_key()
                # 保存密钥到文件
                self.save_key_to_file(video_key.hex(), 'video_key.txt')
                self.save_key_to_file(str(image_key, 'utf-8'), 'image_key.txt')  # 注意转换Fernet密钥为字符串
        else:
            video_key = self.generate_video_key()
            image_key = self.generate_image_key()
            # 保存密钥到文件
            self.save_key_to_file(video_key.hex(), 'video_key.txt')
            self.save_key_to_file(str(image_key, 'utf-8'), 'image_key.txt')  # 注意转换Fernet密钥为字符串
        # 源文件夹
        if model == 'encrypt':
            self.batch_process(model, input_folder, output_folder_encrypt, video_key,image_key)
        elif model == 'decrypt':
            self.batch_process(model, input_folder, output_folder_decrypt, video_key, image_key)
        else:
            print("未选择处理方式")

    def batch_process(self, mode, input_folder, output_folder, video_key=None, image_key=None):
        """预处理"""
        total_files = sum([len(files) for _, _, files in os.walk(input_folder)])
        processed_files = 0

        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        with ThreadPoolExecutor() as executor:
            futures = []
            for root, _, files in os.walk(input_folder):
                for filename in files:
                    full_input_path = os.path.join(root, filename)
                    base_name, ext = os.path.splitext(filename)
                    ext_lower = ext.lower()

                    if ext_lower in ['.jpg', '.jpeg', '.png']:
                        if mode == 'encrypt':
                            future = executor.submit(self.encrypt_image, full_input_path, output_folder, image_key)
                        elif mode == 'decrypt':
                            future = executor.submit(self.decrypt_image, full_input_path, output_folder, image_key)
                    elif ext_lower in ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.mpg', '.mpeg', '.3gp',
                                       '.webm']:
                        output_file_path = os.path.join(output_folder, f"{base_name}_{mode}{ext}")
                        if mode == 'encrypt':
                            future = executor.submit(self.encrypt_video, full_input_path, output_file_path, video_key)
                        elif mode == 'decrypt':
                            future = executor.submit(self.decrypt_video, full_input_path, output_file_path, video_key)
                    else:
                        print(f"Ignoring unsupported file type for operation '{mode}': {filename}")

                    if future is not None:
                        futures.append(future)

            for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures),
                               desc=f"{mode.capitalize()}ing files", unit="file"):
                processed_files += 1
                tqdm.write(f"\rTotal: {total_files}, Processed: {processed_files}", end='')

        tqdm.write(f"\nFinished processing {processed_files} out of {total_files} files.")

    def encrypt_video(self, input_file, output_file, video_key):
        """加密视频"""
        cipher = AES.new(video_key, AES.MODE_CBC)
        # 假设我们读取前几个字节作为文件头，后面是有效载荷
        with open(input_file, 'rb') as in_file:
            header = in_file.read(16)  # 示例：读取16字节文件头
            payload = in_file.read()
        iv = cipher.iv
        ciphertext = cipher.encrypt(self.pad_data(payload))
        with open(output_file, 'wb') as out_file:
            out_file.write(header)  # 写回原文件头
            out_file.write(struct.pack('16s', iv))  # 写入IV
            out_file.write(ciphertext)

    def decrypt_video(self, encrypted_file, output_file, video_key):
        """解密视频"""
        with open(encrypted_file, 'rb') as in_file:
            header = in_file.read(16)
            iv = in_file.read(16)
            ciphertext = in_file.read()
        cipher = AES.new(video_key, AES.MODE_CBC, iv=iv)
        plaintext = self.unpad_data(cipher.decrypt(ciphertext))
        with open(output_file, 'wb') as out_file:
            out_file.write(header)  # 写回原文件头
            out_file.write(plaintext)

    def pad_data(self, data, block_size=AES.block_size):
        # 使用PKCS7进行填充
        padding_length = block_size - len(data) % block_size
        return data + bytes([padding_length]) * padding_length

    def unpad_data(self, data):
        # 使用PKCS7移除填充
        padding_length = data[-1]
        if 0 < padding_length <= AES.block_size and all(byte == padding_length for byte in data[-padding_length:]):
            return data[:-padding_length]
        else:
            raise ValueError("Invalid padding")

    def generate_video_key(self):
        """获取视频密钥"""
        return get_random_bytes(32)  # 假设使用256位密钥长度

    def generate_image_key(self):
        """获取图片密钥"""
        return Fernet.generate_key()

    def save_key_to_file(self, key, filename):
        """保存密钥到指定的文件中"""
        with open(filename, 'wb' if isinstance(key, bytes) else 'w') as key_file:
            key_file.write(key)


    def read_file_to_key(self, model,read_file_name):
        """读取文件中的key"""
        with open(read_file_name, 'r') as file:
            key = file.read().strip()
        if model == 'video':
            key = bytes.fromhex(key)
        return key

    def file_has_content(self,file_path):
        """判断文件是否有内容"""
        try:
            # 尝试打开文件
            with open(file_path, 'r') as file:
                # 读取第一行内容
                first_line = file.readline().strip()
                # 如果读取到的行不为空，则说明文件有内容
                return bool(first_line)
        except IOError:
            # 文件不存在或无法打开时捕获异常
            return False

    def encrypt_image(self, input_path, output_dir,image_key):
        """加密图片"""
        # 获取原始文件名和扩展名
        base_name = os.path.basename(input_path)
        file_name, ext = os.path.splitext(base_name)
        # 打开图片并转换为PNG格式
        with Image.open(input_path) as img:
            img.save('temp.png')
        # 加密临时PNG文件并写入输出目录
        with open('temp.png', 'rb') as file:
            data = file.read()
        cipher_suite = Fernet(image_key)
        encrypted_data = cipher_suite.encrypt(data)
        output_path = os.path.join(output_dir, f'{file_name}.encrypted.bin')
        with open(output_path, 'wb') as out_file:
            out_file.write(encrypted_data)

    def decrypt_image(self, input_path, output_dir,image_key):
        """解密图片"""
        # 获取原始文件名（假设输入的是加密文件）
        base_name = os.path.basename(input_path)
        file_name = os.path.splitext(base_name)[0]
        # 读取加密文件并解密
        with open(input_path, 'rb') as file:
            encrypted_data = file.read()
        cipher_suite = Fernet(image_key)
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        # 将解密后的内容写回为PNG图片并存到输出目录
        temp_output = f'decrypted_temp.png'
        with open(temp_output, 'wb') as out_file:
            out_file.write(decrypted_data)
        # 将PNG图片转换回原始格式并保存
        img = Image.open(temp_output)
        original_ext = '.jpg'  # 假设原图是JPG格式，可根据实际情况调整
        output_path = os.path.join(output_dir, f'{file_name}{original_ext}')
        # 假设 img 是已经解密并加载到 PIL.Image 对象中的图像
        if img.mode == 'RGBA':
            # 转换为 RGB 模式并丢弃 Alpha 通道（透明度）
            img = img.convert('RGB')
        # 现在可以安全地以 JPEG 格式保存了
        img.save(output_path, format='JPEG')
        # img.save(output_path)
        # 删除临时文件
        os.remove(temp_output)

if __name__ == '__main__':
    # 加密方式
    model='encrypt'  # decrypt
    # 源文件夹
    input_folder = 'original'
    # 加密文件夹
    output_folder_encrypt = 'encrypted'
    # 解密文件夹
    output_folder_decrypt = 'decrypted'
    # 图片加密密钥
    # image_key = 'Y-GGKXSzwywaYfcZrOcAxq3yLijuD_-_Oy7I77bvX_o='
    image_key = None
    # 视频加密密钥
    # video_key = b'\x7fVG\r\x94\xd8\xb96\x10p/\x83\x1a\x00o\xf0_\xc2*O\xd7;`\xce\xf2\xf1&m\x8a\xec}\x80'
    video_key = None
    # 实例化
    Encrypt(model,input_folder,output_folder_encrypt,output_folder_decrypt,video_key,image_key)
