import hashlib
import secrets
import base58 
from datetime import datetime

class Keys:
    def __init__(self):
        self.p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.a = 0
        self.b = 7
        self.gX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        self.gY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
        self.G = (self.gX, self.gY)
        self.privateKey = hex(secrets.randbits(256))[2:] 
        self.publicKey = self.getPublicKey(self.privateKey)

    def ecDivide(self, a, b):
        lm, hm = 1,0
        low, high = a%b,b
        while low > 1:
            ratio = int(high/low)
            nm, new = hm-lm*ratio, high-low*ratio
            lm, low, hm, high = nm, new, lm, low
        return lm % b

    def ecAdd(self, a, b):
        LamAdd = ((b[1]-a[1]) * self.ecDivide(b[0]-a[0], self.p)) % self.p
        x = (LamAdd*LamAdd-a[0]-b[0]) % self.p
        y = (LamAdd*(a[0]-x)-a[1]) % self.p
        return (x,y)
        
    def ecDouble(self, a):
        Lam = ((3*a[0]*a[0]+self.a) * self.ecDivide(2*a[1], self.p)) % self.p
        x = (Lam*Lam-2*a[0]) % self.p
        y = (Lam*(a[0]-x)-a[1]) % self.p
        return (x,y)

    def ecMultiply(self,a,b):
        if type(b) == str:
            ScalarBin = str(format(int(str(b), 16), "040b"))
        else:
            ScalarBin = str(bin(b))[2:]
        Q = a
        for i in range (1, len(ScalarBin)): 
            Q=self.ecDouble(Q); 
            if ScalarBin[i] == "1":
                Q=self.ecAdd(Q,a);
        return (Q)

    def getPublicKey(self,a):
        if int(a, 16) == 0 or int(a, 16) >= self.n:
            raise Exception("Invalid Private Key!")
        publicKey = self.ecMultiply(self.G, a)
        uncompressedPublicKey = "04" + "%064x" % publicKey[0] + "%064x" % publicKey[1]
        compressedPublicKey = ""
        if publicKey[1] % 2 == 1:
            compressedPublicKey = "03"+str(hex(publicKey[0])[2:]).zfill(64)
        else:
            compressedPublicKey = "02"+str(hex(publicKey[0])[2:]).zfill(64)
        return compressedPublicKey 

class Wallet:
    def __init__(self,publicKey):
        self.publicKey = publicKey
        self.address = self.getAddress(publicKey)

    def getAddress(self, publicKey):
        bytesPublicKey = bytes.fromhex(publicKey) 
        firstSHA256 = hashlib.sha256(bytesPublicKey).digest()
        RIPEMD160 = hashlib.new('ripemd160')
        RIPEMD160.update(firstSHA256)
        hexRIPEMD160 = RIPEMD160.hexdigest()
        mainnetKey = b'\x00' + RIPEMD160.digest()
        secondSHA256 = hashlib.sha256(mainnetKey).digest()
        thirdSHA256 = hashlib.sha256(secondSHA256).digest()
        checksum = thirdSHA256.hex()[:8]
        bytesAddress = bytes.fromhex("00" + hexRIPEMD160 + checksum)
        address = base58.b58encode(bytesAddress).decode('utf-8')
        return address
        
class Transaction:
    def __init__(self, fromAddress, toAddress, amount, secretKeys):
        self.time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.fromAddress = fromAddress
        self.toAddress = toAddress
        self.amount = amount
        self.ecMultiply = secretKeys.ecMultiply
        self.ecDivide = secretKeys.ecDivide
        self.ecAdd = secretKeys.ecAdd
        self.privateKey = secretKeys.privateKey 
        self.publicKey = secretKeys.publicKey
        self.G = secretKeys.G
        self.publicKeys = self.ecMultiply(self.G, self.privateKey)
        self.n = secretKeys.n
        self.hash = self.calculateHash() 

    def calculateHash(self):
        if self.fromAddress == None:
            return hashlib.sha256((self.toAddress + str(self.amount)).encode('utf-8')).hexdigest()
        return hashlib.sha256((self.fromAddress + self.toAddress + str(self.amount)).encode('utf-8')).hexdigest()

    def signTransaction(self):
        if Wallet(self.publicKey).address == self.fromAddress: 
            randomNum = secrets.randbits(256) 
            xSignPoint, ySignPoint = self.ecMultiply(self.G, randomNum)
            r = xSignPoint%self.n
            s = ((int(self.hash, 16) + r * int(self.privateKey,16)) * self.ecDivide(randomNum, self.n))%self.n
            return (r,s)
        else:
            return False
            
    def verifySignature(self, signature):
        r = signature[0]
        s = signature[1]
        w = self.ecDivide(s, self.n)
        xu1, yu1 = self.ecMultiply(self.G, ((int(self.hash,16) * w)%self.n))
        xu2, yu2 = self.ecMultiply(self.publicKeys, ((r*w)%self.n))
        x, y = self.ecAdd((xu1, yu1), (xu2, yu2))
        return r == x

    def isTransactionValid(self):
        signature = self.signTransaction()
        if signature:
            return self.verifySignature(signature)
        return False

class MiningReward:
    def __init__(self, miningRewardAddress, miningReward):
        self.time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.toAddress = miningRewardAddress
        self.amount = miningReward
        self.fromAddress = None

    def isTransactionValid(self):
        return True

class Block:
    def __init__(self, transactions):
        self.nonce = 0
        self.time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.previousHash = ""
        self.transactions = transactions
        self.hash = self.calculateHash()

    def calculateHash(self):
        return hashlib.sha256((str(self.time) + self.previousHash + str(self.transactions) + str(self.nonce)).encode('utf-8')).hexdigest()

    def mineBlock(self, difficulty):
        while self.hash[:difficulty] != difficulty * "0":
            self.nonce += 1
            self.hash = self.calculateHash()

    def hasValidTransactions(self):
        for i in self.transactions:
            if i.isTransactionValid() != True:
                return False
        return True

class Blockchain:
    def __init__(self):
        self.chain = [Block([Transaction(user0Address, user1Address, 1, user0)])]
        self.difficulty = 2
        self.pendingTransactions = []
        self.miningReward = 10

    def getLatestBlock(self):
        return self.chain[-1]

    def addTransaction(self, transaction):
        fromAddress = transaction.fromAddress
        amount = transaction.amount
        if fromAddress and transaction.toAddress and amount:
            balance = self.getAddressBalance(fromAddress)
            if balance < amount:
                raise Exception("Transaction invalid!")
            if transaction.isTransactionValid() == False:
                raise Exception("Transaction invalid!")
            self.pendingTransactions.append(transaction)
        else:
            raise Exception("Transaction invalid!")
        

    def minePendingTransactions(self, miningRewardAddress):
        block = Block(self.pendingTransactions)
        if block.hasValidTransactions():
            block.previousHash = self.getLatestBlock().hash
            block.mineBlock(self.difficulty)
            self.chain.append(block) 
            self.pendingTransactions = [MiningReward(miningRewardAddress, self.miningReward)]
        else:
            raise Exception("Block has invalid transactions!")

    def getAddressBalance(self, address):
        balance = 0
        for i in self.chain:
            for j in i.transactions:
                if j.fromAddress == address:
                    balance -= j.amount
                elif j.toAddress == address:
                    balance += j.amount
        return balance
                
    def isChainValid(self):
        for i in range(len(self.chain)):
            currentBlock = self.chain[i]

            if currentBlock.hash != currentBlock.calculateHash():
                return False
            if currentBlock.hasValidTransactions() == False:
                return False
            if i != 0:
                previousBlock = self.chain[i-1]
                if currentBlock.previousHash != previousBlock.hash:
                    return False

        return True

def JSONBlockchain(blockchain):
    chain = []
    for i in blockchain.chain:
        block = []
        for j in i.transactions: 
            transaction = {"FROM": j.fromAddress, "TO": j.toAddress, "AMOUNT": j.amount, "TIME": j.time}
            block.append(transaction)
        chain.append(block)
    return chain

user0 = Keys()
user1 = Keys()
user0Address = Wallet(user0.publicKey).address
user1Address = Wallet(user1.publicKey).address
crypto = Blockchain()
crypto.addTransaction(Transaction(user1Address, user0Address, 1, user1))
crypto.minePendingTransactions(user0Address)
crypto.minePendingTransactions(user0Address)
crypto.addTransaction(Transaction(user0Address, user1Address, 3, user0))
crypto.addTransaction(Transaction(user0Address, user1Address, 5, user0))
crypto.minePendingTransactions(user0Address)
print(JSONBlockchain(crypto))
