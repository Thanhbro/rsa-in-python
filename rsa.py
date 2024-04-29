import random
from math import gcd
import tkinter as tk

def ktr_is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
Is_prime = [n for n in range(1000, 100000) if ktr_is_prime(n)]

def generate_N_key():
    p = random.choice(Is_prime)
    q = random.choice(Is_prime)
    while p == q:
        q = random.choice(Is_prime)
    n = p * q
    return n

def generate_Phin_key(p, q):
    Phin = (p - 1) * (q - 1)
    return Phin

def generate_e_key(p, q):
    Phin = generate_Phin_key(p, q)
    for e in range(random.randrange(1, Phin), Phin):
        if gcd(e, Phin) == 1:
            return e

def generate_d_key(e, p, q):
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return d

def endecrypt_mes(m, e, n):
    m %= n
    if m==0:
        return 0
    result = pow(m, e, n)
    return result

def decrypt_mes(c, d, n):
    c %= n
    if c==0:
        return 0
    ciphertext = pow(c, d, n)
    return ciphertext


def convert_str_to_dec(input_str):
    return [ord(char) for char in input_str]

def convert_dec_to_str(input_dec):
    return ''.join([chr(num) for num in input_dec])

N = generate_N_key()
p = random.choice(Is_prime)
q = random.choice(Is_prime)
while not (ktr_is_prime(p) and ktr_is_prime(q)):
    p = random.choice(Is_prime)
    q = random.choice(Is_prime)

n = p * q
Phin = generate_Phin_key(p, q)
e = generate_e_key(p, q)
d = generate_d_key(e, p, q)



# CODE Giao diện

# Tạo cửa sổ giao diện
win = tk.Tk()
win['bg']= 'yellow'
win.title(" RSA NHÓM 12",)

win.geometry("600x550")
def encode_mes():
    message = entry_message.get()
    encrypted = [endecrypt_mes(ord(char), e, n) for char in message]
    entry_encoded.delete(0, tk.END)
    entry_encoded.insert(0, str(encrypted))

def decode_mes():
    encrypted_str = entry_encoded.get().strip('[]')
    decrypted = ''.join([chr(endecrypt_mes(int(num), d, n)) for num in encrypted_str.split(', ')])
    entry_decoded.delete(0, tk.END)
    entry_decoded.insert(0, decrypted)

def reset_all():
    entry_message.delete(0, tk.END)
    entry_encoded.delete(0, tk.END)
    entry_decoded.delete(0, tk.END)
    label_p.config(text="p: {"  "}")
    label_q.config(text="q: {"  "}")
    public_key.config(text="Public key {e, n}: ")
    private_key.config(text="Private key {d, n}: ")

def regenerate_keys():
    global p, q, e, n, d
    p = random.choice(Is_prime)
    q = random.choice(Is_prime)
    while p == q:
        q = random.choice(Is_prime)
        p = random.choice(Is_prime)
    n = p * q
    Phin = (p - 1) * (q - 1)
    e = generate_e_key(p, q)
    d = generate_d_key(e, p, q)
    label_p.config(text="p: {" + str(p) +"}")
    label_q.config(text="q: {" + str(q) + "}")
    public_key.config(text="Public key {e, n}: {" + str(e) + ", " + str(n) + "}")
    private_key.config(text="Private key {d, n}: {" + str(d) + ", " + str(n) + "}")

# Tạo và định vị các thành phần trong giao diện
name =tk.Label(win,text='1.Chọn 2 sô nguyên tố ngẫu nhiên  ',font=("Time New Roman", 14))
name.pack()

label_p = tk.Label(win, text="p: {" + str(p) + "}", font=("Time New Roman", 15))
label_p.pack()


label_q = tk.Label(win, text="q: {" + str(q) + "}", font=("Time New Roman", 15))
label_q.pack()

nam1 = tk.Label(win, text=" 2.Khóa công khai ", font=("Time New Roman", 15))
nam1.pack()

public_key = tk.Label(win, text="Public key {e, n}: {" + str(e) + ", " + str(n) + "}", font=("Time New Roman", 15))
public_key.pack()

nam2= tk.Label(win, text=" 3.Khóa bí mật ", font=("Time New Roman", 15))
nam2.pack()

private_key = tk.Label(win, text="Private key {d, n}: {" + str(d) + ", " + str(n) + "}", font=("Time New Roman", 15))
private_key.pack()


message = tk.Label(win, text="Thông điệp:", font=("Time New Roman", 15))
message.pack()

entry_message = tk.Entry(win, width=50, font=("Time New Roman", 15))
entry_message.pack()

button_encrypt = tk.Button(win, text="Mã hóa", command=encode_mes, font=("Time New Roman", 15))
button_encrypt.pack()

label_encoded = tk.Label(win, text="Encoded Message:", font=("Time New Roman", 15))
label_encoded.pack()

entry_encoded = tk.Entry(win, width=50, font=("Time New Roman", 15))
entry_encoded.pack()a

button_decrypt = tk.Button(win, text="Giải mã", command=decode_mes, font=("Time New Roman", 15))
button_decrypt.pack()

label_decoded = tk.Label(win, text="Decoded Message:", font=("Time New Roman", 15))
label_decoded.pack()

entry_decoded = tk.Entry(win, width=50, font=("Time New Roman", 15))
entry_decoded.pack()

button_reset_all = tk.Button(win, text="Reset All", command=reset_all, font=("Time New Roman", 15))
button_reset_all.pack()
button_regenerate_key = tk.Button(win, text="Khởi tạo lại khóa ", command=regenerate_keys, font=("Time New Roman", 15))
button_regenerate_key.pack()
if __name__ == '__main__':
    win.mainloop()
