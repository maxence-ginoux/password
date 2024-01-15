import re
import hashlib

def get_password():
    while True:
        password = input("Entrez un mot de passe : ")
        if (len(password) < 8 or
                not re.search(r'[A-Z]', password) or
                not re.search(r'[a-z]', password) or
                not re.search(r'\d', password) or
                not re.search(r'[!@#$%^&*]', password)):
            print("Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial (!, @, #, $, %, ^, &, *)")
        else:
            return password

def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

password = get_password()
hashed_password = hash_password(password)
print("Le mot de passe haché est : ", hashed_password)