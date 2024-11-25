import re
import hashlib

def check_password_strength(password):
    
    if len(password) < 8:
        return "Пароль должен быть не менее 8 символов."
    
    if not re.search(r'[A-Z]', password):
        return "Пароль должен содержать хотя бы одну прописную букву."
    
    if not re.search(r'[a-z]', password):
        return "Пароль должен содержать хотя бы одну строчную букву."
    
    if not re.search(r'\d', password):
        return "Пароль должен содержать хотя бы одну цифру."
    
    return "Пароль достаточно сложный."

def hash_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed

password = input("Введите пароль: ")

strength_message = check_password_strength(password)
print(strength_message)

if strength_message == "Пароль достаточно сложный.":
    hashed_password = hash_password(password)
    print("Хэш-значение вашего пароля:", hashed_password)
