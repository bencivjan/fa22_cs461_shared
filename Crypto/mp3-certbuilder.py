from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Util import number
import datetime
import hashlib

# Utility to make a cryptography.x509 RSA key object from p and q
def make_privkey(p, q, e=65537):
    n = p*q
    d = number.inverse(e, (p-1)*(q-1))
    iqmp = rsa.rsa_crt_iqmp(p, q)
    dmp1 = rsa.rsa_crt_dmp1(e, p)
    dmq1 = rsa.rsa_crt_dmq1(e, q)
    pub = rsa.RSAPublicNumbers(e, n)
    priv = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
    pubkey = pub.public_key(default_backend())
    privkey = priv.private_key(default_backend())
    # privkey = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2047)
    # pubkey = privkey.public_key()
    return privkey, pubkey

# The ECE422 CA Key! Your cert must be signed with this.
ECE422_CA_KEY, _ = make_privkey(10079837932680313890725674772329055312250162830693868271013434682662268814922750963675856567706681171296108872827833356591812054395386958035290562247234129,13163651464911583997026492881858274788486668578223035498305816909362511746924643587136062739021191348507041268931762911905682994080218247441199975205717651)

# Skeleton for building a certificate. We will require the following:
# - COMMON_NAME matches your netid.
# - COUNTRY_NAME must be US
# - STATE_OR_PROVINCE_NAME must be Illinois
# - issuer COMMON_NAME must be ece422
# - 'not_valid_before' date must must be March 1
# - 'not_valid_after'  date must must be March 27
# Other fields (such as pseudonym) can be whatever you want, we won't check them

# 12:a9:36:63:39:7a:67:16:6c:53:72:65:9a:a6:6a:f2:6f:66:c2:59
def make_cert(netid, pubkey, ca_key = ECE422_CA_KEY, serial=int('12a93663397a67166c5372659aa66af26f66c259', 16)):
    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(datetime.datetime(2017, 3, 1))
    builder = builder.not_valid_after (datetime.datetime(2017, 3, 27))
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, str(netid)),
        x509.NameAttribute(NameOID.PSEUDONYM, u'unused' + '1'*57),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Illinois'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'ece422'),
]))
    builder = builder.serial_number(serial)
    builder = builder.public_key(pubkey)
    cert = builder.sign(private_key=ECE422_CA_KEY, algorithm=hashes.MD5(), backend=default_backend())
    return cert

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print('usage: python mp3-certbuilder <netid> <outfile.cer>')
        sys.exit(1)
    netid = sys.argv[1]
    outfile = sys.argv[2]
    # p = number.getPrime(1024)
    # q = number.getPrime(1024)

    p1 = 2456391213147082189909627057653381285318162095022390551401988545347763066019969254568151828138380007641999059993245638640514355619693095868726662544541
    q1 = 3516047683236968815660263052001598341897436400305482156811725558852361023273069673793578642945598476947483658604403983962279653503432118183041900986167249836372924675353326016245105674588185360632863981462708256048755312853169192448756743860738799757547345787999160873261228694725054091870927426342163274940343335294251087016329458440706706384915808420592641180489410477083564031748325170010728783469499136782980555318353762743524870246746726161470224366676396998077
    p2 = 2290751672187218111670352094172223673458512414652524872991198951767176299264135282651174941369929417925020529603466506804238629154329355276700595818249
    q2 = 3770285858118792978362439272894804252970267346954615586732289036221718540558063627881487236092047054823224940812323259013426743580668819671611996270944877565866051076847798701471025701042865412127178098001643579101146129207821826491427930410325166394307269762153592726367361232474569625381354720971801801964100610238547089325222097552329739919877797717997534109822606538239188578364845030646250347873613807615176794039561497990990061155234839634884978153286283305697

    privkey, pubkey = make_privkey(p2, q2)
    # print(len(pubkey), type(pubkey))
    cert = make_cert(netid, pubkey)
    print('md5 of cert.tbs_certificate_bytes:', hashlib.md5(cert.tbs_certificate_bytes).hexdigest())

    # print( hex(pubkey.public_numbers().n) )

    # We will check that your certificate is DER encoded
    # We will validate it with the following command:
    #    openssl x509 -in {yourcertificate.cer} -inform der -text -noout
    with open(outfile, 'wb') as f:
        f.write(cert.public_bytes(Encoding.DER))
    print('try the following command: openssl x509 -in %s -inform der -text -noout' % outfile)

    # with open('tbs_certificate_bytes_dump.hex', 'wb') as f:
    #     f.write(cert.tbs_certificate_bytes)

    # with open('tbs_cert_prefix.hex', 'wb') as f:
    #     f.write(cert.tbs_certificate_bytes[:256])