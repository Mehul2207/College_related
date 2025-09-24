"""
Simplified Hospital Management System (Menu-driven)
Roles: Patient, Doctor, Auditor

Dependencies:
    pip install pycryptodome

Features:
- Patient: upload & encrypt record (AES), sign (RSA), view past records.
- Doctor: decrypt record, hash with SHA512, verify patient signature.
- Auditor: view metadata, verify signatures (with plaintext if provided).
"""

import os, json, base64, hashlib
from datetime import datetime, timezone
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

KEYS_DIR, DATA_DIR = 'keys', 'data'
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# --- Helpers ---
def pad(d): return d + bytes([16 - len(d)%16])*(16-len(d)%16)
def unpad(d): return d[:-d[-1]]
def sha512(d): return hashlib.sha512(d).digest()

def key_paths(role,id):
    return f"{KEYS_DIR}/{role}_{id}_priv.pem", f"{KEYS_DIR}/{role}_{id}_pub.pem"

def ensure_keys(role,id):
    priv,pub=key_paths(role,id)
    if not os.path.exists(priv):
        k=RSA.generate(2048)
        open(priv,'wb').write(k.export_key())
        open(pub,'wb').write(k.publickey().export_key())

def load_priv(role,id): return RSA.import_key(open(key_paths(role,id)[0],'rb').read())
def load_pub(role,id): return RSA.import_key(open(key_paths(role,id)[1],'rb').read())

def aes_enc(pt):
    k,iv=get_random_bytes(32),get_random_bytes(16)
    ct=AES.new(k,AES.MODE_CBC,iv).encrypt(pad(pt))
    return k,iv,ct

def aes_dec(k,iv,ct): return unpad(AES.new(k,AES.MODE_CBC,iv).decrypt(ct))

# --- Record handling ---
def rec_dir(pid): d=f"{DATA_DIR}/{pid}/records"; os.makedirs(d,exist_ok=True); return d

def save_record(pid,fname,ct,meta):
    ts=datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    p=f"{rec_dir(pid)}/{ts}_{fname}.enc"
    open(p,'wb').write(ct); open(p+'.json','w').write(json.dumps(meta,indent=2))
    return p

def list_records(pid):
    d=rec_dir(pid)
    return [(f"{d}/{f}", f"{d}/{f}.json") for f in os.listdir(d) if f.endswith('.enc')]

# --- Menus ---
def patient():
    pid=input('Patient ID: '); ensure_keys('patient',pid)
    while True:
        c=input("1) Upload record 2) View records 0) Back: ")
        if c=='0':break
        if c=='1':
            txt=input("Enter record text: ").encode()
            did=input("Doctor ID: "); ensure_keys('doctor',did)
            k,iv,ct=aes_enc(txt)
            enc_k=PKCS1_OAEP.new(load_pub('doctor',did)).encrypt(k)
            sig=pkcs1_15.new(load_priv('patient',pid)).sign(SHA512.new(txt))
            meta={'pid':pid,'did':did,'ts':datetime.now(timezone.utc).isoformat(),'sig':base64.b64encode(sig).decode(),'iv':base64.b64encode(iv).decode(),'ekey':base64.b64encode(enc_k).decode()}
            save_record(pid,'rec.txt',ct,meta)
        elif c=='2':
            for f in list_records(pid): print(f)

def doctor():
    did=input('Doctor ID: '); ensure_keys('doctor',did)
    pid=input('Patient ID: ')
    for f,_ in list_records(pid): print(f)
    f=input('File to decrypt: ')
    ct=open(f,'rb').read(); meta=json.load(open(f+'.json'))
    k=PKCS1_OAEP.new(load_priv('doctor',did)).decrypt(base64.b64decode(meta['ekey']))
    pt=aes_dec(k,base64.b64decode(meta['iv']),ct)
    print('Plaintext:',pt.decode())
    sig_ok=False
    try: pkcs1_15.new(load_pub('patient',pid)).verify(SHA512.new(pt),base64.b64decode(meta['sig'])); sig_ok=True
    except: pass
    print('Signature valid' if sig_ok else 'Signature invalid')

def auditor():
    pid=input('Patient ID: ')
    for f,_ in list_records(pid):
        meta=json.load(open(f+'.json'))
        print(f,meta)

# --- Main ---
while True:
    r=input("1) Patient 2) Doctor 3) Auditor 0) Exit: ")
    if r=='0':break
    {'1':patient,'2':doctor,'3':auditor}.get(r,lambda:None)()

import os, json, base64, hashlib
from datetime import datetime, timezone
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

KEYS_DIR, DATA_DIR = 'keys', 'data'
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# --- Helpers ---
def pad(d): return d + bytes([16 - len(d)%16])*(16-len(d)%16)
def unpad(d): return d[:-d[-1]]
def sha512(d): return hashlib.sha512(d).digest()

def key_paths(role,id):
    return f"{KEYS_DIR}/{role}_{id}_priv.pem", f"{KEYS_DIR}/{role}_{id}_pub.pem"

def ensure_keys(role,id):
    priv,pub=key_paths(role,id)
    if not os.path.exists(priv):
        k=RSA.generate(2048)
        open(priv,'wb').write(k.export_key())
        open(pub,'wb').write(k.publickey().export_key())

def load_priv(role,id): return RSA.import_key(open(key_paths(role,id)[0],'rb').read())
def load_pub(role,id): return RSA.import_key(open(key_paths(role,id)[1],'rb').read())

def aes_enc(pt):
    k,iv=get_random_bytes(32),get_random_bytes(16)
    ct=AES.new(k,AES.MODE_CBC,iv).encrypt(pad(pt))
    return k,iv,ct

def aes_dec(k,iv,ct): return unpad(AES.new(k,AES.MODE_CBC,iv).decrypt(ct))

# --- Record handling ---
def rec_dir(pid): d=f"{DATA_DIR}/{pid}/records"; os.makedirs(d,exist_ok=True); return d

def save_record(pid,fname,ct,meta):
    ts=datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    p=f"{rec_dir(pid)}/{ts}_{fname}.enc"
    open(p,'wb').write(ct); open(p+'.json','w').write(json.dumps(meta,indent=2))
    return p

def list_records(pid):
    d=rec_dir(pid)
    return [(f"{d}/{f}", f"{d}/{f}.json") for f in os.listdir(d) if f.endswith('.enc')]

# --- Menus ---
def patient():
    pid=input('Patient ID: '); ensure_keys('patient',pid)
    while True:
        c=input("1) Upload record 2) View records 0) Back: ")
        if c=='0':break
        if c=='1':
            txt=input("Enter record text: ").encode()
            did=input("Doctor ID: "); ensure_keys('doctor',did)
            k,iv,ct=aes_enc(txt)
            enc_k=PKCS1_OAEP.new(load_pub('doctor',did)).encrypt(k)
            sig=pkcs1_15.new(load_priv('patient',pid)).sign(SHA512.new(txt))
            meta={'pid':pid,'did':did,'ts':datetime.now(timezone.utc).isoformat(),'sig':base64.b64encode(sig).decode(),'iv':base64.b64encode(iv).decode(),'ekey':base64.b64encode(enc_k).decode()}
            save_record(pid,'rec.txt',ct,meta)
        elif c=='2':
            for f in list_records(pid): print(f)

def doctor():
    did=input('Doctor ID: '); ensure_keys('doctor',did)
    pid=input('Patient ID: ')
    for f,_ in list_records(pid): print(f)
    f=input('File to decrypt: ')
    ct=open(f,'rb').read(); meta=json.load(open(f+'.json'))
    k=PKCS1_OAEP.new(load_priv('doctor',did)).decrypt(base64.b64decode(meta['ekey']))
    pt=aes_dec(k,base64.b64decode(meta['iv']),ct)
    print('Plaintext:',pt.decode())
    sig_ok=False
    try: pkcs1_15.new(load_pub('patient',pid)).verify(SHA512.new(pt),base64.b64decode(meta['sig'])); sig_ok=True
    except: pass
    print('Signature valid' if sig_ok else 'Signature invalid')

def auditor():
    pid=input('Patient ID: ')
    for f,_ in list_records(pid):
        meta=json.load(open(f+'.json'))
        print(f,meta)

# --- Main ---
while True:
    r=input("1) Patient 2) Doctor 3) Auditor 0) Exit: ")
    if r=='0':break
    {'1':patient,'2':doctor,'3':auditor}.get(r,lambda:None)()