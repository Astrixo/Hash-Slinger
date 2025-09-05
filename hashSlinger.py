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
ROCKYOUHASHES = ['sha512', 'sha256', 'sha224', 'sha384'] #Random hashes for level 3 DICT
BARRIER = "#########################################" # I don't want to type my barrier out for block more than once
LOWERLETTERS = "abcdefghijklmnopqrstuvwxyz" #Lowercase letters for mask attacks
UPPERLETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" #Uppercase letters for mask attacks
DIGITS = "1234567890" #Digits for mask attacks
MASK_FOUR_CHARS = "abc123" #Characters for mask level 4
SPECIAL_CHARS = '!"#$%&()*+,-./:;<=>?@^_{|}~' #Special characters for mask attacks
MASK_FIVE_CHARS = UPPERLETTERS + DIGITS + SPECIAL_CHARS # Characters for mask level 5

#Picks random line from file (E.G Password or Rule)
def pick_randomLine(file):
    with open(file, 'r', encoding='utf-8', errors='ignore') as awesomeFile:
        lines = awesomeFile.readlines()
        return random.choice(lines).strip()

#Level one for dictionary attacks. MD5 hashes random line from smallRockYou.txt
def dict_one():
    block("LEVEL ONE")
    print('General: You will be given an MD5 Hash of a password randomly picked from the RockYou wordlist.')
    print('Instructions: Enter the plaintext password associated with this MD5 Hash.')
    print('Hint: hashcat -a 0 -m 0 <hash.txt> /usr/share/wordlists/rockyou.txt')
    password = pick_randomLine("./wordlists/smallRockYou.txt")
    print(f'Target Hash: {hash("md5", password)}')
    guess(password)

#Level two for dictionary attacks. Sha256 hashes random line from smallRockYou.txt
def dict_two():
    block("LEVEL TWO")
    print('General: Good job on solving the MD5 Hash. This one is SHA256.')
    print('Instructions: Enter the plaintext password associated with this SHA256 Hash.')
    print('Hint: It will not be -m 0. It will be -m 1400')
    password = pick_randomLine("./wordlists/smallRockYou.txt")
    print(f'Target Hash: {hash("sha256", password)}')
    guess(password)

#Level three for dictionary attacks. Random hashes random line from smallRockYou.txt
def dict_three():
    block("LEVEL THREE")
    print('General: Nice! Now I\'m going to give you a hash without telling you the algorithm.')
    print('Instructions: Enter the plaintext password associated with this unkown Hash.')
    print('Hint: Run hashcat on the file with no arguments to find the hash type')
    password = pick_randomLine("./wordlists/smallRockYou.txt")
    hashType = random.choice(ROCKYOUHASHES)
    print(f'Target Hash: {hash(hashType, password)}')
    guess(password)

#Level four for dictionary attacks. Theoretically supposed to apply random rule from nsa64.rule but like, it doesnt work.
def dict_four():
    block("LEVEL FOUR")
    print('General: Now that you have figured out how to identify hashes. I\'m going to give you something new. Rules')
    print('Instructions: Enter the plaintext password associated with this random Hash.')
    print('Hint: Run the same hashcat command you\'ve been running but add -r rules/nsa64.rule')
    password = pick_randomLine("./wordlists/smallRockYou.txt")
    rule = pick_randomLine("./rules/nsa64.rule")
    hashType = random.choice(ROCKYOUHASHES)
    print(f'Target Hash: {hash(hashType, password)}')
    guess(password)

#Level five for dictionary attacks. Idk what this one is gonna do, prolly something with rules.
def dict_five():
    block("LEVEL FIVE")
    print("How in the hell did you call this function???")
    print("More General: NVM")

#Level one for mask attacks. MD5 hashes "CyberUnit" with two random numbers at the end.
def mask_one():
    block("LEVEL ONE")
    print('General: Mask attacks are type of brute forcing. The idea is that you know some of the password and you are guessing the rest')
    print('Instructions: Return the password associated with the provided md5 hash.')
    print('Password Format: The password is "CyberUnit" with 2 numbers added to the end.')
    print("Hint: Run hashcat -a3 -m0 hash.txt CyberUnit?d?d")
    password = "CyberUnit" + str(random.randint(0, 9)) + str(random.randint(0, 9))
    print(f"Target Hash: {hash('md5', password)}")
    guess(password)

#Level two for mask attacks. MD5 hashes "CyberUnit" with two lowercase letters at the start and two uppercase letters at the end.
def mask_two():
    block("LEVEL TWO")
    print('General: Seems like you got the hang of it! Now let\'s add some letters!')
    print('Instructions: Return the password associated with the provided MD5 hash.')
    print('Password Format: The password is "CyberUnit" with two lowercase letters at the front and two uppercase letters at the end')
    print('Hint: ?u for uppercase and ?l for lowercase')
    password = random.choice(LOWERLETTERS) + random.choice(LOWERLETTERS) + "CyberUnit" + random.choice(UPPERLETTERS) + random.choice(UPPERLETTERS)
    print(f"Target Hash: {hash('md5', password)}")
    guess(password)

#Level three for mask attacks. MD5 hashes a string of 7 random numbers.
def mask_three():
    block("LEVEL THREE")
    print('General: Nice! You\'re doing great! Mask attacks can also just brute force passwords.')
    print('Instructions: Return the password associated with the provided MD5 hash.')
    print('Password Format: The password is 7 random numbers.')
    print('Hint: Your mask will look like ?d?d?d?d?d?d?d')
    password = [random.randint(0, 9) for _ in range(7)]
    password = "".join(str(i) for i in password)
    print(f"Target Hash: {hash('md5', password)}")
    guess(password)

#Level four for mask attacks. MD5 hashes 10 character long string comprised of abc123
def mask_four():
    block("LEVEL FOUR")
    print('General: Wow, you totally bruteforced that number. We have been using hashcat\'s prebuilt mask rules but did you know we can make our own?')
    print('Instructions: Return the password associated with the provided MD5 hash.')
    print('Password Format: The password is 10 characters long and is a random comination of abc123.')
    print('Hint: Make a custom mask rule by doing "-1 abc123 ?1?1" (but with 10 of the ?1)')
    password = [random.choice(MASK_FOUR_CHARS) for _ in range(10)]
    password = "".join(str(i) for i in password)
    print(f"Target Hash: {hash('md5', password)}")
    guess(password)

#Level five. Makes 5character long strings comprised of digits, specical characters, and uppercase. 
def mask_five():
    block("LEVEL FIVE")
    print("General: Good job making the custom mask! You can also make custom masks using hashcat's prebuilt masks.")
    print('Instructions: Return the password associated with the provdied MD5 hash.')
    print('Password Format: The password is a random combination of 5 uppercase, numbers, and special characters.')
    print('Hint: Make a custom mask using prexisitng masks by doing "-1 ?u?s?d"')
    password = [random.choice(MASK_FIVE_CHARS) for _ in range(5)]
    password = "".join(str(i) for i in password)
    print(f"Target Hash: {hash('md5', password)}")
    guess(password)

#Returns hash of provided string
def hash(algo: str, s: str) -> str:
    try:
        return hashlib.new(algo, s.encode('utf-8')).hexdigest()
    except ValueError:
        print(f"{YELLOWTEXT}[!] Unsupported algorithm: {algo}")
        sys.exit(1)

#Loops until user inputs the correct password.
def guess(password):
    print(YELLOWTEXT + 'Type "exit" to quit the level.' + RETURNDEFAULTCOLOR)
    guess = input("Guess: ")
    while guess != password:
        if guess.upper() == "EXIT":
            return
        print(f'{REDTEXT}Nope, try again :){RETURNDEFAULTCOLOR}')
        guess = input("Guess: ")
    print(f'{GREENTEXT}Correct!{RETURNDEFAULTCOLOR}')

#Prints Block message because I'm lazy and don't want to type it out each time.
def block(message):
    print(BARRIER)
    print(f'##{BLUETEXT}{message.center(len(BARRIER)-4)}{RETURNDEFAULTCOLOR}##')
    print(BARRIER)

#Organizational function for dictionary attacks. (add pick levels?)
def dictionary_attacks():
    block("Dictionary Attacks")
    print("Which level do you want to do?")
    print("  [1] Level 1 - Filler\n  [2] Level 2 - Filler\n  [3] Level 3 - Filler\n  [4] Level 4 - Filler\n  [5] Level 5 - Filler\n  [Q] Quit to main menu")
    level = str(input("Level: ")).upper()
    while level not in dict_level_handlers:
        print(REDTEXT + "PICK A VALID LEVEL NUMBER" + RETURNDEFAULTCOLOR)
        level = str(input("Level: ")).upper()
    handler = dict_level_handlers[level]
    handler()
    dictionary_attacks()

#Organizational function for mask attacks. (add pick levels?)
def mask_attacks():
    block("Mask Attacks")
    mask_one()
    mask_two()
    mask_three()
    mask_four()
    mask_five()

#Placeholder function for combinator attacks
def combinator_attacks():
    block("In development")

#Function for quitting the program (just for organizational / readability)
def quitter():
    print(REDTEXT + "[!] Quitting..." + RETURNDEFAULTCOLOR)
    print("Feel free to reachout if you have any suggestions!")
    sys.exit(0)

def quit_to_menu():
    print(REDTEXT + "Qutting to menu" + RETURNDEFAULTCOLOR)
    pick_module()

#Menu to pick what you want to work on.
def pick_module():
    block("Pick a Module")
    print("  [1] Dictionary Attacks\n  [2] Mask Attacks\n  [3] Combinator attacks (NOT ADDED)\n  [Q] Quit Program")
    answer = str(input("Module: ")).upper()
    while answer not in menu_handlers:
        print(f"{REDTEXT}THAT IS NOT A VALID ANSWER >:[{RETURNDEFAULTCOLOR}")
        answer = str(input("Module: ")).upper()
    handler = menu_handlers[answer]
    handler() 

#Pick a level
def pick_level():
    print("Picking a level...")

#Defines handlers to make menu... better?
menu_handlers = {
    "1": dictionary_attacks,
    "2": mask_attacks,
    "3": combinator_attacks,
    "Q": quitter
}

#Defines dictionary level handlers
dict_level_handlers = {
    "1": dict_one,
    "2": dict_two,
    "3": dict_three,
    "4": dict_four,
    "5": dict_five,
    "Q": quit_to_menu
}

#Defines mask level handlers
mask_level_handlers = {
    "1": mask_one,
    "2": mask_two,
    "3": mask_three,
    "4": mask_four,
    "5": mask_five
}

#Prints a message after a user wins
def win():
    print("Congratulations! This concludes the levels currently available!")
    print("Play again for even more training.")
    print('''
        *                                             * 
                                          *
               *
                             *
                                                       *
    *
                                             *
        *
                      *             *
                                                *
 *                                                               *
          *
                          (             )
                  )      (*)           (*)      (
         *       (*)      |             |      (*)
                  |      |~|           |~|      |          *
                 |~|     | |           | |     |~|
                 | |     | |           | |     | |
                ,| |a@@@@| |@@@@@@@@@@@| |@@@@a| |.
           .,a@@@| |@@@@@| |@@@@@@@@@@@| |@@@@@| |@@@@a,.
         ,a@@@@@@| |@@@@@@@@@@@@.@@@@@@@@@@@@@@| |@@@@@@@a,
        a@@@@@@@@@@@@@@@@@@@@@' . `@@@@@@@@@@@@@@@@@@@@@@@@a
        ;`@@@@@@@@@@@@@@@@@@'   .   `@@@@@@@@@@@@@@@@@@@@@';
        ;@@@`@@@@@@@@@@@@@'     .     `@@@@@@@@@@@@@@@@'@@@;
        ;@@@;,.aaaaaaaaaa       .       aaaaa,,aaaaaaa,;@@@;
        ;;@;;;;@@@@@@@@;@      @.@      ;@@@;;;@@@@@@;;;;@@;
        ;;;;;;;@@@@;@@;;@    @@ . @@    ;;@;;;;@@;@@@;;;;;;;
        ;;;;;;;;@@;;;;;;;  @@   .   @@  ;;;;;;;;;;;@@;;;;@;;
        ;;;;;;;;;;;;;;;;;@@     .     @@;;;;;;;;;;;;;;;;@@@;
    ,%%%;;;;;;;;@;;;;;;;;       .       ;;;;;;;;;;;;;;;;@@;;%%%,
 .%%%%%%;;;;;;;@@;;;;;;;;     ,%%%,     ;;;;;;;;;;;;;;;;;;;;%%%%%%,
.%%%%%%%;;;;;;;@@;;;;;;;;   ,%%%%%%%,   ;;;;;;;;;;;;;;;;;;;;%%%%%%%,
%%%%%%%%`;;;;;;;;;;;;;;;;  %%%%%%%%%%%  ;;;;;;;;;;;;;;;;;;;'%%%%%%%%
%%%%%%%%%%%%`;;;;;;;;;;;;,%%%%%%%%%%%%%,;;;;;;;;;;;;;;;'%%%%%%%%%%%%
`%%%%%%%%%%%%%%%%%,,,,,,,%%%%%%%%%%%%%%%,,,,,,,%%%%%%%%%%%%%%%%%%%%'
  `%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'
      `%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'
             """"""""""""""`,,,,,,,,,'"""""""""""""""""
                            `%%%%%%%'
                             `%%%%%'
                               %%%     
                              %%%%%
                           .,%%%%%%%,.
                      ,%%%%%%%%%%%%%%%%%%%,
''')

#Main...
def main():
    block("Preparing the Hash Slinger Training")
    while True:
        pick_module()


if __name__ == '__main__':
    main()
