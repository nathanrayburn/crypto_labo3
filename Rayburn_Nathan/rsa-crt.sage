from hashlib import sha256

def key_gen():
    phi = 2
    e = 2
    while gcd(phi, e) != 1 : 
        p = random_prime(2**1024, proof = False)
        q = random_prime(2**1024, proof = False)
        n = p*q
        phi = (p-1) * (q-1)
        e = 65537
    d = inverse_mod(e, phi)
    return (e, d, n, p, q)

def sign(m, d, p, q, n):
    dp = d % (p-1)
    dq = d % (q-1)
    h = int.from_bytes(sha256(m).digest(), byteorder = "big")
    #Nous introduisons ici le bug
    sp = ZZ.random_element(p)# Nous simulons ici le bug. Vrai code: power_0mod(h, dp, p)
    
    print("SP = %s" % str(sp))
    sq = power_mod(h, dq, q)
    return crt([sp, sq], [p, q])
def signatureWorking(m, d, p, q, n):
    dp = d % (p-1)
    dq = d % (q-1)
    h = int.from_bytes(sha256(m).digest(), byteorder = "big")
 
    sp =  power_mod(h, dp, p)
    
    print("SP = %s" % str(sp))
    sq = power_mod(h, dq, q)
    return crt([sp, sq], [p, q])
def generate():
    (e, d, n, p, q) = key_gen()
    m = b"This message is signed with RSA-CRT!"
    s = sign(m, d, p, q, n)
    print("e = %s" % str(e))
    print("n = %s" %str(n))
    print("s = %s" %s)

    s = sign(m, d, p, q, n)

    hackSignature(e,n,m,s)

def validateSignature(m,s,e,n):
    h = int.from_bytes(sha256(m).digest(), byteorder = "big")
    mprime = power_mod(s,e,n)
    print(f" if {mprime} == {h}")
    if mprime == h:
        return true
    return false
def hackSignature(e,n,m,s):
    ###### RSA-CRT

    mprime = power_mod(s,e,n)
    h = int.from_bytes(sha256(m).digest(), byteorder = "big")
    
    print(f"mprime : {mprime}")
    print(f"message hash: {h}")

    p = gcd(h-mprime,n)
    q = n/p
    d = power_mod(e,-1, (p-1)*(q-1))

    print(f"P = {p}")
    print(f"Q = {q}")
    print(f"D = {d}")
    
    test_signature = signatureWorking(m,d,p,q,n)

    if validateSignature(m,test_signature,e,n):
        print("Signature ok")
    else:
        print("Signature nok")
    

generate()


e = 65537
n = 8829698272894796058566294092055666782872126452750807746555129369227000637915857695428589221511341057523554836694948298377206605673001847013450476796871448913174360477004444607389087584357727518299033629868519198822751284169469680098414714541716948386952961247701034777505689426686201261498980737011046001071171449279898522731197730323564329841958313813700923015955159238715899303115169749085139629355398114518746006337398240588074810472007815336056659179004878034646656318786354262301047895193398137616079757158792272194731937616111683678235365021658262013896963561471722012329950791120004360807901173024461520224493
m = b'This message is signed with RSA-CRT!'
s = 1190917722554178976753284795976688079717481278145993359514513523002036421742572019056865149314632211957040146691028385960597271303411600301272701748873052408939851883089095533903577536549890067654008607578494850765837313788269107848805351486952352373644128856961650613358088819654810410851390931346123802667127784725039647324201895017876605812491526421344457190986345555060175226121768598324888030825387334263332374598728878741248557873773083893721574459604443324611561844080894155789143922264867919685671883927600397121829193609647416838947723115309462560898899772203749883537650525041944263193976056655064867573514


hackSignature(e,n,m,s)

