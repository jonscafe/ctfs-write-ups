def key_scheduling(key):
    sched = [i for i in range(0, 256)]
    
    i = 0
    for j in range(0, 256):
        i = (i + sched[j] + key[j % len(key)]) % 256
        
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp
        
    return sched
    

def stream_generation(sched):
    stream = []
    i = 0
    j = 0
    while True:
        i = (1 + i) % 256
        j = (sched[i] + j) % 256
        
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp
        
        yield sched[(sched[i] + sched[j]) % 256]        


def encrypt(text, key):
    text = [ord(char) for char in text]
    
    sched = key_scheduling(key)
    key_stream = stream_generation(sched)
    
    ciphertext = ''
    for char in text:
        enc = str("{:02x}".format(char ^ next(key_stream)))
        ciphertext += (enc)
        
    return ciphertext
    