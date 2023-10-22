while True:
    ip = input("AEGIS> ")
    if 'hint' in ip.lower():
        print(__import__('os').system('cat jail.py'))
        exit()
    try:
        print(eval(ip, {"__builtins__": {}}, {"__builtins__": {}}))
    except Exception as error:
        print("ERROR:", error)
        print("Good luck next time!")
        pass