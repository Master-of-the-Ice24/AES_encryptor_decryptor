from tkinter import *
from Crypto.Cipher import AES


class mainWindow:
    def __init__(self):
        self.root = Tk()
        self.window()

    def window(self):
        self.root.attributes("-zoomed", True)
        self.root.title("AES encryptor/decryptor")
        self.screenWidth = self.root.winfo_screenwidth()
        self.screenHeight = self.root.winfo_screenheight()

        self.encryption = Frame(self.root)
        self.encryption.pack(expand=True,
                             fill=BOTH, 
                             side=LEFT, 
                             pady=self.screenHeight//100,
                             padx=self.screenWidth//60)

        self.decryption = Frame(self.root)
        self.decryption.pack(expand=True,
                             fill=BOTH, 
                             side=RIGHT, 
                             pady=self.screenHeight//100,
                             padx=self.screenWidth//60)

        ########################

        self.encLabel = Label(self.encryption,
                            text="Encryption", 
                            font=("Arial", 18),
                            background="light gray")
        self.encLabel.pack(fill=X, 
                            pady=self.screenHeight//20,
                            side=TOP)
        
        self.encryptionTextLabel = Label(self.encryption, 
                                    text="Message: ",
                                    font=("Arial", 14))
        self.encryptionTextLabel.pack(expand=False, 
                                fill=X, 
                                side=TOP)
        self.encryptionText = Text(self.encryption,
                                height=round(self.screenHeight//200), 
                                font=("Arial", 14))
        self.encryptionText.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)

        self.encryptionKeyLabel = Label(self.encryption, 
                                    text="16-bytes key (16 characters): ", 
                                    font=("Arial", 14))
        self.encryptionKeyLabel.pack(expand=False, 
                                fill=X, 
                                side=TOP)
        self.encryptionKey = Entry(self.encryption, 
                                show="*",
                                font=("Arial", 14))
        self.encryptionKey.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)

        self.encryptionButton = Button(self.encryption,
                                        command=self.encryptMsg, 
                                        text="Encrypt",
                                        font=("Arial", 14))
        self.encryptionButton.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)

        self.encryptionOutputLabel = Label(self.encryption, 
                                    text="Encrypted message: ",
                                    font=("Arial", 14))
        self.encryptionOutputLabel.pack(expand=False, 
                                fill=X, 
                                side=TOP)
        self.encryptionOutput = Text(self.encryption,
                                height=round(self.screenHeight//200), 
                                font=("Arial", 14))
        self.encryptionOutput.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)
        
        self.encryptionTagLabel = Label(self.encryption, 
                                    text="Tag: ",
                                    font=("Arial", 14))
        self.encryptionTagLabel.pack(expand=False, 
                                fill=X, 
                                side=TOP)
        self.encryptionTag = Entry(self.encryption,
                                font=("Arial", 14))
        self.encryptionTag.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)

        self.encryptionNonceLabel = Label(self.encryption, 
                                    text="Nonce: ",
                                    font=("Arial", 14))
        self.encryptionNonceLabel.pack(expand=False, 
                                fill=X, 
                                side=TOP)
        self.encryptionNonce = Entry(self.encryption,
                                font=("Arial", 14))
        self.encryptionNonce.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)

        #####
        #####

        self.decLabel = Label(self.decryption,
                            text="Decryption", 
                            font=("Arial", 18),
                            background="light gray")
        self.decLabel.pack(fill=X, 
                            pady=self.screenHeight//20,
                            side=TOP)

        self.decryptionTextLabel = Label(self.decryption, 
                                    text="Encrypted message: ",
                                    font=("Arial", 14))
        self.decryptionTextLabel.pack(expand=False, 
                                fill=X, 
                                side=TOP)
        self.decryptionText = Text(self.decryption,
                                height=round(self.screenHeight//200), 
                                font=("Arial", 14))
        self.decryptionText.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)

        self.decryptionKeyLabel = Label(self.decryption, 
                                    text="16-bytes key (16 characters): ", 
                                    font=("Arial", 14))
        self.decryptionKeyLabel.pack(expand=False, 
                                fill=X, 
                                side=TOP)
        self.decryptionKey = Entry(self.decryption, 
                                show="*",
                                font=("Arial", 14))
        self.decryptionKey.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)
        
        self.decryptionTagLabel = Label(self.decryption, 
                                    text="Tag: ",
                                    font=("Arial", 14))
        self.decryptionTagLabel.pack(expand=False, 
                                fill=X, 
                                side=TOP)
        self.decryptionTag = Entry(self.decryption,
                                font=("Arial", 14))
        self.decryptionTag.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)

        self.decryptionNonceLabel = Label(self.decryption, 
                                    text="Nonce: ",
                                    font=("Arial", 14))
        self.decryptionNonceLabel.pack(expand=False, 
                                fill=X, 
                                side=TOP)
        self.decryptionNonce = Entry(self.decryption, 
                                font=("Arial", 14))
        self.decryptionNonce.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)

        self.decryptionButton = Button(self.decryption,
                                        command=self.decryptMsg, 
                                        text="Decrypt",
                                        font=("Arial", 14))
        self.decryptionButton.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)

        self.decryptionOutputLabel = Label(self.decryption, 
                                    text="Decrypted message: ",
                                    font=("Arial", 14))
        self.decryptionOutputLabel.pack(expand=False, 
                                fill=X, 
                                side=TOP)
        self.decryptionOutput = Text(self.decryption,
                                height=round(self.screenHeight//200), 
                                font=("Arial", 14))
        self.decryptionOutput.pack(expand=False, 
                                fill=X, 
                                side=TOP,
                                pady=self.screenHeight//60)
        
        self.root.mainloop()


    def encryptMsg(self):
        data = self.encryptionText.get("1.0", "end-1c").encode()
        aes_key = self.encryptionKey.get().encode()

        cipher = AES.new(aes_key, AES.MODE_OCB)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        assert len(cipher.nonce) == 15

        self.encryptionOutput.insert("1.0", ciphertext.hex())
        self.encryptionTag.insert(0, tag.hex())
        self.encryptionNonce.insert(0, cipher.nonce.hex())

    
    def decryptMsg(self):
        ciphertext = self.decryptionText.get("1.0", "end-1c")
        tag = self.decryptionTag.get()
        nonce = self.decryptionNonce.get()
        aes_key = self.decryptionKey.get().encode()

        ciphertext = bytes.fromhex(ciphertext)
        tag = bytes.fromhex(tag)
        nonce = bytes.fromhex(nonce)

        assert len(nonce) == 15

        cipher = AES.new(aes_key, AES.MODE_OCB, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        self.decryptionOutput.insert("1.0", plaintext.decode())



if __name__ == "__main__":
    app = mainWindow()

