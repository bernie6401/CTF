while True:
    ip = input("AEGIS> ")
    if 'hint' in ip.lower():
        print(__import__('os').system('cat jail.py'))
        exit()
    try:
        if 'flag' in ip.lower():
            print("Sorry, I don't like any \"FLAG\"!")
            continue
        print(eval(ip))
    except Exception as error:
        print("ERROR:", error)
        print("Good luck next time!")
        pass