MODE_ECB = 1
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    x = a[0] ^ a[1] ^ a[2] ^ a[3]
    y = a[0]
    a[0] ^= x ^ xtime(a[0] ^ a[1])
    a[1] ^= x ^ xtime(a[1] ^ a[2])
    a[2] ^= x ^ xtime(a[2] ^ a[3])
    a[3] ^= x ^ xtime(a[3] ^ y)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))  # c1 & c3
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


# mang chua hang so sd trong cac vl
r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def bytes_to_matrix(text):
    """ Chuyển đổi mảng 16 byte thành ma trận 4x4.  """
    return [list(text[i:i + 4]) for i in range(0, len(text), 4)]


# 4pt 4byte lap4 4/ mỗi 4byte chuyen thanh ds con 4pt, them dsc 4x4
def matrix_to_bytes(matrix):
    """ Chuyển đổi ma trận 4x4 thành mảng 16 byte. """
    return bytes(sum(matrix, [])) #lam phang ma tran - ds1c


def xor_bytes(a, b):
    """ Trả về một mảng byte mới với các phần tử được xor'ed """
    return bytes(i ^ j for i, j in zip(a, b))


# ghep cap pt 2 mag ab, vs i j
def pad(plaintext):
    """
        them gtr vao plaitx để đủ 16byte
    """
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)  # tao 1 mag byte co do dai =pdlen
    return plaintext + padding


def unpad(plaintext):
    """
    loại bỏ padding từ dữ liệu plaintext
    """
    padding_len = plaintext[-1]  # độ dài của padding từ byte cuối cùng của plaintext.
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]  # tach2p dl goc va padding
    assert all(p == padding_len for p in padding)  # ktr.. cac byte tr pad gtr do dai = pading
    return message


def split_blocks(message, block_size=16, require_padding=True):  # chia thanh cac khoi16byte
    assert len(message) % block_size == 0 or not require_padding
    return [message[i:i + 16] for i in range(0, len(message), block_size)]
    # lặp qua message và chia nó thành các khối có độ dài block_size


class AES:
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}  # ánh xạ độ dài của khóa AES byte

    def __init__(self, master_key):
        """
        Khởi tạo đối tượng bằng một khóa nhất định.
        """
        assert len(master_key) in AES.rounds_by_key_size  # kiểm tra độ dài
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]  # xác định số vòng lặp
        self._key_matrices = self._expand_key(master_key)  # mở rộng khóa chính

    def _expand_key(self, master_key):
        """
        Mở rộng và trả về danh sách các ma trận khóa cho master_key đã cho.
        """
        key_columns = bytes_to_matrix(master_key)  # chuyển đổi master_key thành ma trận 4x4
        iteration_size = len(master_key) // 4  # xd kthuoc

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:  # sl cot trong () < số vòng lặp cần thiết AES /+1bđ
            # coppy pha tu khoa cuoi.
            word = list(key_columns[-1])

            if len(key_columns) % iteration_size == 0:  # kiểm tra () (kt laplai) hay không
                # dich vong tuan tu.
                word.append(word.pop(0))
                # asnh xa cac bytes qa Sbox
                word = [s_box[b] for b in word]
                # XOR với byte đầu tiên của R-CON
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:

                word = [s_box[b] for b in word]

            # XOR từ khóa hiện tại với từ khóa tương ứng từ vòng lặp trước đó
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Nhóm các từ khóa trong ma trận 4x4 byte.
        return [key_columns[4 * i: 4 * (i + 1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        """
        mã hóa một khối dữ liệu văn bản (plaintext) có độ dài 16 byte
        """
        assert len(plaintext) == 16

        plain_state = bytes_to_matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])  # XOR giữa ma trận trạng thái và khóa vòng đầu tiên

        for i in range(1, self.n_rounds):  # lap 1-cc
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix_to_bytes(plain_state)
        # Chuyển đổi ma trận trạng thái đã mã hóa thành dạng byte

    def decrypt_block(self, ciphertext):
        """
        giải mã một khối dữ liệu mã hóa (ciphertext) có độ dài 16 byte
        """
        assert len(ciphertext) == 16

        cipher_state = bytes_to_matrix(ciphertext)  # chuyen ciphtx thanh mt tt

        add_round_key(cipher_state, self._key_matrices[-1])  # xor vs khoa cc
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])  # XOR giữa ma trận trạng thái và khóa vòng tương ứng
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)

        add_round_key(cipher_state, self._key_matrices[0])  # XOR giữa ma trận trạng thái và khóa vòng đầu tiên

        return matrix_to_bytes(cipher_state)

    def encrypt_ecb(self, plaintext):
        plaintext = pad(plaintext)  # add padding
        blocks = []  # ds rông luu tru khoi mh
        for plaintext_block in split_blocks(plaintext):
            block = self.encrypt_block(plaintext_block)
            blocks.append(block)
        return b''.join(blocks)

    # ket hop khoi mh vao 1 chuoi byte duy nhat
    def decrypt_ecb(self, ciphertext):
        blocks = []
        for ciphertext_block in split_blocks(ciphertext):
            blocks.append(self.decrypt_block(ciphertext_block))
        return unpad(b''.join(blocks))  # loai bo byte padding


# hmac tt mã xthuc tren 1 khoapriv va ham bam
import os
from hashlib import pbkdf2_hmac  # tao khoa dua tren 1 mk va salt (tang do mah) = cach sd n`` vong lap, 1 hbam mmm
from hmac import new as new_hmac, compare_digest

AES_KEY_SIZE = 16
HMAC_KEY_SIZE = 16  # một phương thức để tạo mã xác thực cho dữ liệu
IV_SIZE = 16

SALT_SIZE = 16  # một giá trị ngẫu nhiên được sử dụng trong quá trình tạo khóa từ mật khẩu bằng cách sử dụng hàm PBKDF2
HMAC_SIZE = 32  # Độ dài của mã xác thực được tạo ra bởi HMAC


def get_key_iv(password, salt, workload=100000):
    """
    workload (số lần lặp lại). Dùng để tạo khóa AES, khóa HMAC và IV từ mật khẩu và muối.
    """
    stretched = pbkdf2_hmac('sha256', password, salt, workload, AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE)
    # Tách kết quả đã phát triển thành khóa AES, khóa HMAC và vector khởi tạo AES.
    aes_key, stretched = stretched[:AES_KEY_SIZE], stretched[
                                                   AES_KEY_SIZE:]  # Các byte đầu tiên của kết quả phát triển là khóa AES.
    hmac_key, stretched = stretched[:HMAC_KEY_SIZE], stretched[HMAC_KEY_SIZE:]
    iv = stretched[:IV_SIZE]
    return aes_key, hmac_key, iv


def encrypt(key, plaintext, mode=MODE_ECB, workload=100000):
    print("\nAES128 ENCRYPT", end='\t')
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):  # Chuyển đổi key và plaintext từ chuỗi sang dạng byte nếu chúng là chuỗi Unicode.
        plaintext = plaintext.encode('utf-8')
    """
        Hàm này thực hiện việc mã hóa plaintext bằng khóa key sử dụng thuật toán AES-128 trong chế độ ECB  
        và sử dụng HMAC để xác thực tính toàn vẹn của dữ liệu sau khi đã mã hóa.
    """
    salt = os.urandom(SALT_SIZE)
    key, hmac_key, iv = get_key_iv(key, salt, workload)  # tạo khóa AES, khóa HMAC và vector khởi tạo

    if mode == MODE_ECB:
        print("(ECB MODE)")
        # Convert ciphertext from bytes to base64
        ciphertext = AES(key).encrypt_ecb(plaintext)
    hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert len(hmac) == HMAC_SIZE

    # Convert ciphertext from bytes to base64
    ciphertext_base64 = b64encode(hmac + salt + ciphertext).decode()
    return ciphertext_base64


# Chuyển dữ liệu đã mã hóa và HMAC sang dạng base64 và kết hợp tạo ra chuỗi dữ liệu cuối

from base64 import b64encode, b64decode


def decrypt(key, ciphertext_base64, mode=MODE_ECB, workload=100000):
    """
        HMAC để xác minh tính toàn vẹn,
        và PBKDF2 để kéo dài khóa đã cho.

    """
    ciphertext = b64decode(ciphertext_base64.encode())
    print("\nAES128 DECRYPT", end='\t')
    assert len(ciphertext) % 16 == 0, "các khối 16 byte đầy đủ"

    assert len(ciphertext) >= 32, """
        Bản mã phải dài ít nhất 32 byte (16 byte muối + 16 byte khối)
        """
    if isinstance(key, str):
        key = key.encode('utf-8')

    hmac, ciphertext = ciphertext[:HMAC_SIZE], ciphertext[HMAC_SIZE:]
    salt, ciphertext = ciphertext[:SALT_SIZE], ciphertext[SALT_SIZE:]
    key, hmac_key, iv = get_key_iv(key, salt, workload)

    if mode == MODE_ECB:
        print("(ECB MODE)")
        plaintext = AES(key).decrypt_ecb(ciphertext)
        return plaintext.decode('utf-8')


def base64_to_hex(text_base64):  # hàm trả về dữ liệu đã giải mã dưới dạng UTF-8.
    return b64encode(text_base64.encode()).hex()


from tkinter import *
from base64 import b64encode, b64decode


# Import các hàm mã hóa và giải mã AES từ đoạn mã trước

def encrypt_message():
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    mode = mode_var.get()

    try:
        ciphertext_base64 = encrypt(key, plaintext, mode)
        ciphertext_entry.delete(0, END)
        ciphertext_entry.insert(0, ciphertext_base64)
    except Exception as e:
        messagebox.showerror("Error", str(e))


def decrypt_message():
    ciphertext_base64 = ciphertext_entry.get()
    key = key_entry.get()
    mode = mode_var.get()

    try:
        plaintext_utf_8 = decrypt(key, ciphertext_base64, mode)
        plaintext_entry.delete(0, END)
        plaintext_entry.insert(0, plaintext_utf_8)
    except Exception as e:
        messagebox.showerror("Error roi", str(e))


def clear_fields():
    plaintext_entry.delete(0, END)
    ciphertext_entry.delete(0, END)
    key_entry.delete(0, END)


# Tạo cửa sổ chính
root = Tk()
root.title("AES nhóm 12")
root['bg']='yellow'
root.geometry("600x400")
# Tạo các khung
input_frame = Frame(root)
input_frame.pack(pady=10)

output_frame = Frame(root)
output_frame.pack(pady=10)

button_frame = Frame(root)
button_frame.pack(pady=10)

# Thêm nhãn và ô nhập cho văn bản thô, văn bản mã hóa và khóa
plaintext_label = Label(input_frame, text="Thông điệp:")
plaintext_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
plaintext_entry = Entry(input_frame, width=70)
plaintext_entry.grid(row=0, column=1, padx=10, pady=5)

ciphertext_label = Label(output_frame, text="Thông điệp mã hóa:")
ciphertext_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
ciphertext_entry = Entry(output_frame, width=60)
ciphertext_entry.grid(row=0, column=1, padx=10, pady=5)

key_label = Label(root, text="Khóa:")
key_label.pack(pady=6)
key_entry = Entry(root, width=60)
key_entry.pack()

# Thêm nút radio để chọn chế độ
mode_var = IntVar()
mode_var.set(MODE_ECB)  # Mặc định là chế độ ECB



# Thêm các nút cho việc mã hóa, giải mã và xóa các trường nhập
encrypt_button = Button(button_frame, text="Mã hóa", command=encrypt_message)
encrypt_button.grid(row=0, column=0, padx=5)

decrypt_button = Button(button_frame, text="Giải mã", command=decrypt_message)
decrypt_button.grid(row=0, column=1, padx=5)

clear_button = Button(button_frame, text="Xóa", command=clear_fields)
clear_button.grid(row=0, column=2, padx=5)

# Bắt đầu vòng lặp sự kiện chính
root.mainloop()
