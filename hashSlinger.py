#!/usr/bin/env python3
####################################################
## Author: Astrixo                                ##
## Purpose: Train password cracking               ##
####################################################

#Imports and globals
import argparse, hashlib, random, sys

REDTEXT = "\033[31m" #Wrong
GREENTEXT = "\033[32m" #Success
YELLOWTEXT = "\033[33m" #Errors :(
BLUETEXT = "\033[34m" #I just like this color
RETURNDEFAULTCOLOR = "\033[0m" #Default term color
ROCKYOUHASHES = ['sha512', 'sha256', 'sha224', 'sha384']
BARRIER = "#########################################"

def pick_randomLine():
    with open('./wordlists/smallRockYou.txt', 'r', encoding='utf-8', errors='ignore') as passwordList:
        lines = passwordList.readlines()
        return random.choice(lines).strip()

def dict_one():
    block("LEVEL ONE")
    print('General: You will be given an MD5 Hash of a password randomly picked from the RockYou wordlist.')
    print('Instructions: Enter the plaintext password associated with this MD5 Hash.')
    print('Hint: hashcat -a 0 -m 0 <hash.txt> /usr/share/wordlists/rockyou.txt')
    print('Picking a password...')
    password = pick_randomLine()
    print('Password picked!')
    print(f'Target Hash: {hash("md5", password)}')
    guess(password)

def dict_two():
    block("LEVEL TWO")
    print('General: Good job on solving the MD5 Hash. This one is SHA256.')
    print('Instructions: Enter the plaintext password associated with this SHA256 Hash.')
    print('Hint: It will not be -m 0. It will be -m 1400')
    print('Picking a password...')
    password = pick_randomLine()
    print('Password picked!')
    print(f'Target Hash: {hash("sha256", password)}')
    guess(password)

def dict_three():
    block("LEVEL THREE")
    print('General: Nice! Now I\'m going to give you a hash without telling you the algorithm')
    print('Instructions: Enter the plaintext password associated with this unkown Hash.')
    print('Hint: Run hashcat on the file with no arguments to find the hash type')
    print('Picking a password...')
    password = pick_randomLine()
    print('Password picked!')
    hashType = random.choice(ROCKYOUHASHES)
    print(f'Target Hash: {hash(hashType, password)}')
    guess(password)

def level_four():
    block("LEVEL FOUR")
    print('General: Now that you have figured out how to identify hashes. Im going to give you a random one.')
    print('Instructions: Enter the plaintext password associated with this random Hash.')
    print('Hint: You can use the prebuilt ruleset in this repo.')
    print('Command Format: hashcat -a0 -m0 </path/to/hashes.txt> wordlists/rockyou.txt -r rules/nsa64.rule')
    print('Picking a password...')
    password = pick_randomLine()
    rule = pick_randomRule()
    print('Password picked!')
    print(f'Target Hash: {hash("md5", password)}')
    guess(password)

def dict_five():
    block("LEVEL FIVE")
    print("General: Now we're moving onto something new! Mask attacks.")
    print("More General: NVM")

def hash(algo: str, s: str) -> str:
    try:
        return hashlib.new(algo, s.encode('utf-8')).hexdigest()
    except ValueError:
        print(f"{YELLOWTEXT}[!] Unsupported algorithm: {algo}")
        sys.exit(1)

def guess(password):
    guess = input("Guess: ")
    while guess != password:
        print(f'{REDTEXT}Nope, try again :){RETURNDEFAULTCOLOR}')
        guess = input("Guess: ")
    print(f'{GREENTEXT}Correct!{RETURNDEFAULTCOLOR}')

def block(message):
    print(BARRIER)
    print(f'##{BLUETEXT}{message.center(len(BARRIER)-4)}{RETURNDEFAULTCOLOR}##')
    print(BARRIER)

def dictionary_attacks():
    print(f'##{BLUETEXT}{"Dictionary Attacks".center(len(BARRIER)-4)}{RETURNDEFAULTCOLOR}##')
    level_one()
    level_two()
    level_three()
    level_four()
    level_five()

def pick_module():
    print("What module would you like to work on?")
    answers = ["1", "2", "3"]
    print("  [1] Dictionary Attacks\n  [2] Mask Attacks\n  [3] Combinator attacks")
    answer = str(input("Module: "))
    while answer not in answers:
        print(f"{REDTEXT}THAT IS NOT A VALID ANSWER >:[{RETURNDEFAULTCOLOR}")
        answer = str(input("Guess: "))
    if answer is "1":
        dictionary_attacks()
    elif answer == "2":
        print("This functionality is not added yet rip")
    else:
        print("This functionality is not added yet rip")

def pick_randomRule():
    print("workin")

def win():
    print("Congratulation! This concludes the levels currently available!")
    print("Play again for even more training.")


def main():
    block("Preparing the Hash Slinger Training")
    pick_module()
    win()



if __name__ == '__main__':
    main()
