from os import system
def main():
    status = system("python3 -m pip install netaddr")
    if status == 0:
        print("\033[32m[+]command run seccussfully\033[m")
    else:
        print("\033[33m[-]command run fail")
if __name__ == "__main__":
    main()
