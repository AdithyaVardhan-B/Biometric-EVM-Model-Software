import base64
import os
import sqlite3
import ctypes
from ctypes import wintypes

SECURITY_MAX_SID_SIZE = 68
WINBIO_TYPE_FINGERPRINT = 0x00000008
WINBIO_POOL_SYSTEM = 0x00000001
WINBIO_FLAG_DEFAULT = 0x00000000
WINBIO_ID_TYPE_SID = 3

WINBIO_E_NO_MATCH = 0x80098005          #Error info 

lib = ctypes.WinDLL(r"C:\Windows\System32\winbio.dll")      #Loads windows biometrics dynamic link library(API part)


class GUID(ctypes.Structure):                           #Creating GUID structure to call windows API linked to GUID 
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8)
                ]


class AccountSid(ctypes.Structure):                     #CREATING SECURITY IDENTIFIERS TO CALL BIOMETRIC SENSORS 
    _fields_ = [("Size", wintypes.ULONG),
                ("Data", ctypes.c_ubyte * SECURITY_MAX_SID_SIZE)
                ]


class Value(ctypes.Union):                              #creating a union of above structures and existing templates.
    _fields_ = [("NULL", wintypes.ULONG),
                ("Wildcard", wintypes.ULONG),
                ("TemplateGuid", GUID),
                ("AccountSid", AccountSid)
                ]


class WINBIO_IDENTITY(ctypes.Structure):                #CREATING STRUCTURE OF iDENTITY AND ASSOSIATED VALUE
    _fields_ = [("Type", ctypes.c_uint32),
                ("Value", Value)]


class TOKEN_INFORMATION_CLASS:                      #THESE TOKENS ARE USED IN CALLING BIOMETRIC API'S
    TokenUser = 1
    TokenGroups = 2
    TokenPrivileges = 3


class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):           #CREATING A structure to manipulate the identifier authority portion of the SID.
    _fields_ = [("Value", wintypes.BYTE*6)]


class SID(ctypes.Structure):                                            #STRUCTURE OF SID'S AND AOTHER AUTHENTICATION VALUES IN ONE PLACE
    _fields_ = [("Revision", wintypes.BYTE),
                ("SubAuthorityCount", wintypes.BYTE),
                ("IdentifierAuthority", SID_IDENTIFIER_AUTHORITY),
                ("SubAuthority", wintypes.DWORD)]


class SID_AND_ATTRIBUTES(ctypes.Structure):                     #POINTER STRUCTURE TO DEAL WITH SID
    _fields_ = [("Sid", ctypes.POINTER(SID)),
                ("Attributes", wintypes.DWORD)]


class TOEKN_USER(ctypes.Structure):                             #USER CREATED TOKEN FOR CALLING BIOMETRIC API
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


class FingerPrint:
    def __init__(self):
        self.session_handle = ctypes.c_uint32()
        self.unit_id = ctypes.c_uint32()

        self.subfactor0 = ctypes.c_ubyte(0xf5)       #First Fingerprint
        self.subfactor1 = ctypes.c_ubyte(0xf6)          #Second FIngerprint and so on.....
        self.subfactor2 = ctypes.c_ubyte(0xf7)
        self.subfactor3 = ctypes.c_ubyte(0xf8)
        self.subfactor4 = ctypes.c_ubyte(0xf9)
        self.subfactor5 = ctypes.c_ubyte(0xfa)
        self.subfactor6 = ctypes.c_ubyte(0xfb)
        self.subfactor7 = ctypes.c_ubyte(0xfc)
        self.subfactor8 = ctypes.c_ubyte(0xfd)
        self.subfactor9 = ctypes.c_ubyte(0xfe)       

        self.identity = WINBIO_IDENTITY()
        self.IsOpen = False

    def open(self):                                                                         #STARTING BIOMETRIC SENSOR
        if self.IsOpen:
            return
        ret = lib.WinBioOpenSession(WINBIO_TYPE_FINGERPRINT,  
                                    WINBIO_POOL_SYSTEM,
                                    WINBIO_FLAG_DEFAULT,
                                    None,
                                    0,
                                    None,
                                    ctypes.byref(self.session_handle))  
        if ret & 0xffffffff != 0x0:
            print("Open Failed!")
            return False
        self.IsOpen = True
        return True

    def locate_unit(self):                                                              #LOCATING BIOMETRIC SENSOR
        ret = lib.WinBioLocateSensor(self.session_handle, ctypes.byref(self.unit_id))
        print(self.unit_id)
        if ret & 0xffffffff != 0x0:
            print("Locate Failed!")
            return False
        return True

    def identify(self):                                                 #IDENTIFING FINGERPRINT INPUT AND PRINTING REJECT DETAILS IF REJECTED
        reject_detail = ctypes.c_uint32()
        ret = lib.WinBioIdentify(self.session_handle, ctypes.byref(self.unit_id), ctypes.byref(self.identity),
                                 ctypes.byref(self.subfactor),
                                 ctypes.byref(reject_detail))
        if ret & 0xffffffff != 0x0:
            print(hex(ret & 0xffffffff))
            raise Exception("Identify Error")
        print(f"Unit ID\t:{hex(self.unit_id.value)}")
        print(f"Sub Factor\t:{hex(self.subfactor.value)}")
        print(f"Identity Type\t: {self.identity.Type}")
        print(f"Identity AccountSid Data\t: {list(self.identity.Value.AccountSid.Data)[0:self.identity.Value.AccountSid.Size]}")
        print(f"Identity AccountSid Size\t: {self.identity.Value.AccountSid.Size}")
        print(f"Rejected Details:\t{hex(reject_detail.value)}")

    def verify(self,ayo):                           #VERIFYING FINGERPRINT AND RETURNING TRUE IF MATCHED 
        match = ctypes.c_bool(0)
        reject_detail = ctypes.c_uint32()
        self.get_current_user_identity()
        if ayo == 1:
            ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),                #FINGERPRINT SLOT 1
                                   self.subfactor0, ctypes.byref(self.subfactor0),
                                   ctypes.byref(match), ctypes.byref(reject_detail))
            if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
                del ret
                return match.value
        elif ayo == 2:
            ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),                #FINGERPRINT SLOT 2 AND SOON....
                                   self.subfactor1, ctypes.byref(self.subfactor1),
                                   ctypes.byref(match), ctypes.byref(reject_detail))
            if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
                del ret
                return match.value
        elif ayo == 3:
            ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),
                                   self.subfactor2, ctypes.byref(self.subfactor2),
                                   ctypes.byref(match), ctypes.byref(reject_detail))
            if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
                del ret
                return match.value
        elif ayo == 4:
            ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),
                                   self.subfactor3, ctypes.byref(self.subfactor3),
                                   ctypes.byref(match), ctypes.byref(reject_detail))
            if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
                del ret
                return match.value
        elif ayo == 5:
            ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),
                                   self.subfactor4, ctypes.byref(self.subfactor4),
                                   ctypes.byref(match), ctypes.byref(reject_detail))
            if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
                del ret
                return match.value
        elif ayo == 6:
            ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),
                                   self.subfactor5, ctypes.byref(self.subfactor5),
                                   ctypes.byref(match), ctypes.byref(reject_detail))
            if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
                del ret
                return match.value
        elif ayo == 7:
            ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),
                                   self.subfactor6, ctypes.byref(self.subfactor6),
                                   ctypes.byref(match), ctypes.byref(reject_detail))
            if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
                del ret
                return match.value
        elif ayo == 8:
            ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),
                                   self.subfactor7, ctypes.byref(self.subfactor7),
                                   ctypes.byref(match), ctypes.byref(reject_detail))
            if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
                del ret
                return match.value
        elif ayo == 9:
            ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),
                                   self.subfactor8, ctypes.byref(self.subfactor8),
                                   ctypes.byref(match), ctypes.byref(reject_detail))
            if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
                del ret
                return match.value
        elif ayo == 10:
            ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),
                                   self.subfactor9, ctypes.byref(self.subfactor9),
                                   ctypes.byref(match), ctypes.byref(reject_detail))
            if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
                del ret
                return match.value
            

    def close(self):                                                                    #CLOSING SESSION
        if not self.IsOpen:
            return
        lib.WinBioCloseSession(self.session_handle)
        self.session_handle = 0

    def get_current_user_identity(self):                        #GETTING TOKEN INFORMATION OF CURRENT USER
        self.get_token_information()

    @staticmethod
    def get_process_token():                                    #GETTING PROCESS TOKEN
        """
        Get the current process token
        """
        GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
        GetCurrentProcess.restype = wintypes.HANDLE
        OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
        OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
        OpenProcessToken.restype = wintypes.BOOL
        token = wintypes.HANDLE()


        TOKEN_READ = 0x20008
        res = OpenProcessToken(GetCurrentProcess(), TOKEN_READ, token)
        if not res > 0:
            raise RuntimeError("Couldn't get process token")
        return token

    def get_token_information(self):                            #GET TOKEN INFORMATION OF PROCESS
        """
        Get token info associated with the current process.
        """
        GetTokenInformation = ctypes.windll.advapi32.GetTokenInformation
        GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_uint,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ]
        GetTokenInformation.restype = wintypes.BOOL

        CopySid = ctypes.windll.advapi32.CopySid
        CopySid.argtypes = [
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p
        ]
        CopySid.restype = wintypes.BOOL

        GetLengthSid = ctypes.windll.advapi32.GetLengthSid
        GetLengthSid.argtypes = [
            ctypes.POINTER(SID)
        ]
        GetLengthSid.restype = wintypes.DWORD

        return_length = wintypes.DWORD(0)
        buffer = ctypes.create_string_buffer(SECURITY_MAX_SID_SIZE)

        res = GetTokenInformation(self.get_process_token(),
                                  TOKEN_INFORMATION_CLASS.TokenUser,
                                  buffer,
                                  SECURITY_MAX_SID_SIZE,
                                  ctypes.byref(return_length)
                                  )
        assert res > 0, "Error in second GetTokenInformation (%d)" % res

        token_user = ctypes.cast(buffer, ctypes.POINTER(TOEKN_USER)).contents
        CopySid(SECURITY_MAX_SID_SIZE,
                self.identity.Value.AccountSid.Data,
                token_user.User.Sid
                )
        self.identity.Type = WINBIO_ID_TYPE_SID
        self.identity.Value.AccountSid.Size = GetLengthSid(token_user.User.Sid)
def check_adhr():
    name1=input("Enter your Aadhar Number: ")
    if name1.isdecimal():    
        conn = sqlite3.connect('fingerprint.db')
        cursor = conn.cursor()
        cursor.execute('SELECT EXISTS(SELECT 1 FROM aftable WHERE aadhar = ?)', (name1,))
        result = cursor.fetchone()[0]
        if result:
            print("Aadhar found in database")
            cursor.execute('SELECT finger FROM aftable WHERE aadhar = ?', (name1,))
            ayo1 = cursor.fetchone()[0]
            print("Fingerprint slot used is ",ayo1)
            n=10
            for g in range (11):
                    if __name__ == '__main__':
                        myFP = FingerPrint()
                        try:
                            myFP.open()
                            print("Please touch the fingerprint sensor")
                            if myFP.verify(ayo1):
                                print("Fingerprint Matched")
                                break
                            else:
                                print("Fingerprint not matching with database try again")
                                print(str(n-g)+" number of tries remaining")
                        finally:
                            myFP.close()
            del n,g,ayo1
        else:
            print("Aadhar not found in database")
        conn.commit()
        conn.close()
        os.system('pause')
        os.system('cls')
    else:
        print("Invalid Aadhar Number, The Given Aadhar Number contains character other than numbers")
        os.system('pause')
        os.system('cls')
def add_adhr():
    conn = sqlite3.connect('fingerprint.db')
    cursor = conn.cursor()
    cursor.execute('''
CREATE TABLE IF NOT EXISTS aftable (
    finger INTEGER,
    aadhar TEXT
)
''')
    try:
        h=[1,2,3,4,5,6,7,8,9,10]
        name1=input("Enter Aadhar number: ")
        fc=int(input("Enter the fingerprint SLOT used: "))
        if fc not in h:
            conn.close()
            print("Invalid Fingerprint Slot please select a number between 1 and 10")
            os.system('pause')
            os.system('cls')
        else:
            if name1.isdecimal():
                cursor.execute('SELECT EXISTS(SELECT 1 FROM aftable WHERE finger = ?)', (fc,))
                result = cursor.fetchone()[0]
                if result:
                    h=input("Fingerprint slot already used for another Aadhar do you want to update aadhar linked to given slot?(y/n): ")
                    if h == 'y':
                        conn.execute("UPDATE aftable set aadhar = ? where finger = ?",(name1,fc))
                        print("Aadhar successfully updated")
                        conn.commit()
                        conn.close()
                        os.system('pause')
                        os.system('cls')
                    else:
                        conn.close()
                        os.system('pause')
                        os.system('cls')

                else:
                    cursor.execute('INSERT INTO aftable (aadhar,finger) VALUES (?,?)', (name1,fc))
                    conn.commit()
                    conn.close()
                    print("Aadhar number successfully added to database")
                    os.system('pause')
                    os.system('cls')
            elif name1.isdecimal()==0:
                print("Invalid Aadhar Number, The Given Aadhar Number contains character other than numbers")
                os.system('pause')
                os.system('cls')
    except ValueError:
        print("Invalid Fingerprint Slot please select a number between 1 and 10")
        os.system('pause')
        os.system('cls')
def vote():
    os.system('cls')
    Cand={"Party1":0,"Party2":0,"Party3":0,"Party4":0}
    conn = sqlite3.connect('fingerprint.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS {}'.format('non_voted'))
    conn.commit()
    cursor.execute('CREATE TABLE non_voted AS SELECT * FROM aftable')
    conn.commit()
    cursor.execute('DROP TABLE IF EXISTS {}'.format('voted'))
    conn.commit()
    cursor.execute('''
CREATE TABLE voted (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mystring TEXT)''')
    conn.commit()
    conn.close()
    while True:
        name=input("Enter Your Aadhar number: ")
        if (name=='password@1234'):
            break
        conn = sqlite3.connect('fingerprint.db')
        cursor = conn.cursor()
        cursor.execute('SELECT EXISTS(SELECT 1 FROM non_voted WHERE aadhar = ?)', (name,))
        result = cursor.fetchone()[0]
        cursor.execute('SELECT EXISTS(SELECT 1 FROM voted WHERE mystring = ?)', (name,))
        result1 = cursor.fetchone()[0]
        if result:
            n=10
            cursor.execute('SELECT finger FROM non_voted WHERE aadhar = ?', (name,))
            ayo = cursor.fetchone()[0]
            ayo=int(ayo)
            for g in range (11):
                if __name__ == '__main__':
                    myFP = FingerPrint()
                    try:
                        myFP.open()
                        print("Please touch the fingerprint sensor")
                        if myFP.verify(ayo):
                            print("Fingerprint Matched")
                            while True:
                                print("Which Candidiate Do you want to elect for")
                                print("Select from following list: "+str(list(Cand.keys())))
                                opt=input()
                                if opt in Cand:
                                    Cand[opt]+=1
                                    print("Vote registered")
                                    os.system('pause')
                                    os.system('cls')
                                    break
                                else:
                                    print("Invalid Input, No Party With that name, Try again")
                            cursor.execute('INSERT INTO voted (mystring) VALUES (?)', (name,))
                            conn.commit()
                            cursor.execute('DELETE FROM non_voted WHERE aadhar = ?', (name,))
                            conn.commit()
                            break
                        else:
                            print("Fingerprint not matching with database try again")
                            print(str(n-g)+" number of tries remaining")
                    finally:
                        myFP.close()
            del n,g,ayo
        elif result1:
            print("You've already voted")
            os.system('pause')
        else:
            print("Aadhar number Not found in database")
            os.system('pause')
        conn.close()
        os.system('cls')    
    print("Final Results are \n", Cand)
    os.system('pause')
    with open("results.txt", 'w') as f: 
        for key, value in Cand.items(): 
            f.write('%s:%s\n' % (key, value))
    os.system('cls')
def rem_adhr():
    conn = sqlite3.connect('fingerprint.db')
    cursor = conn.cursor()
    name1=input("Enter Aadhar number: ")
    cursor.execute('DELETE FROM aftable WHERE aadhar = ?', (name1,))
    cursor.execute('DELETE FROM non_voted WHERE aadhar = ?', (name1,))    
    conn.commit()
    conn.close()
    print("Aadhar Number successfully removed from database")
    os.system('pause')
    os.system('cls')

while True:
    What=input("What do you want to do\n1.Add Aadhar number to database\n2.Vote for a candidiate\n3.Remove a Aadhar number from database\n4.Check if Aadhar number and fingerprint exist in database\n5.Exit\n")
    if What == '5':
        break

#Cheking if Aadhar exist in database
    elif What == '4':
        check_adhr()

# Aading aadhar to database
    elif What == '1':
        add_adhr()
        
#Voting for Candidiate
    elif What == '2':
        vote()

#Removing aadhar number from database
    elif What == '3':
        rem_adhr()

#Invalid input case
    else:
        print("Invalid input please try again")
        os.system('pause')
        os.system('cls')
