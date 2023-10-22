while True:
    ip = input("AEGIS> ")
    if 'hint' in ip:
        print(__import__('os').system('cat jail.py'))
        exit()
    try:
        if any (i in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' for i in ip):
            print("I don't like any \"LETTER\"!")
            continue
        print(eval(ip, {"__builtins__": {}}, {"__builtins__": {}}))
    except Exception as error:
        print("ERROR:", error)
        print("Good luck next time!")
        pass