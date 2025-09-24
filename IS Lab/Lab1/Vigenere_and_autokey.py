def vignere_encrypt(str,key):
    n=len(key)
    j=0
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr((ord(str[i])-65+ord(key[j%n])-97)%26+65)
            j=j+1
        elif str[i].islower():
            ans+=chr((ord(str[i])-97+ord(key[j%n])-97)%26+65)
            j=j+1
        else:
            ans+=str[i]
    return ans

def vignere_decrypt(str,key):
    n=len(key)
    j=0
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr((ord(str[i])-65-ord(key[j%n])+97)%26+97)
            j=j+1
        elif str[i].islower():
            ans+=chr((ord(str[i])-97-ord(key[j%n])+97)%26+97)
            j=j+1
        else:
            ans+=str[i]
    return ans

def autokey_encrypt(text, key):
    ans = ""
    key_stream = [key]  # start with the initial numeric key
    j = 0

    for i in range(len(text)):
        if text[i].isspace():
            ans += " "
            continue

        shift = key_stream[j]

        if text[i].isupper():
            c = (ord(text[i]) - 65 + shift) % 26 + 65
            ans += chr(c)
            key_stream.append(ord(text[i]) - 65)  # add plaintext letter as key
        elif text[i].islower():
            c = (ord(text[i]) - 97 + shift) % 26 + 97
            ans += chr(c)
            key_stream.append(ord(text[i]) - 97)
        else:
            ans += text[i]

        j += 1

    return ans


def autokey_decrypt(text, key):
    ans = ""
    key_stream = [key]  # start with the initial numeric key
    j = 0

    for i in range(len(text)):
        if text[i].isspace():
            ans += " "
            continue

        shift = key_stream[j]

        if text[i].isupper():
            p = (ord(text[i]) - 65 - shift) % 26 + 65
            ans += chr(p)
            key_stream.append(ord(chr(p)) - 65)  # recovered plaintext
        elif text[i].islower():
            p = (ord(text[i]) - 97 - shift) % 26 + 97
            ans += chr(p)
            key_stream.append(ord(chr(p)) - 97)
        else:
            ans += text[i]

        j += 1

    return ans

str=input("Enter the message: ")
key="dollars"
res=vignere_encrypt(str,key)
print(res)
dec=vignere_decrypt(res,key)
print(dec)
res2=autokey_encrypt(str,7)
print(res2)
dec2=autokey_decrypt(res2,7)
print(dec2)