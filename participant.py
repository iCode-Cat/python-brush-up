# This is a simple Python script that prints "Hello World!" to the console.
name = 'Alice'
age = None
print(f"Hello {name}")
age = int(input("What is your age?\n"))

if age >= 25:
    print("Sorry, you cannot participate to the party.")
if age < 25:
    print("Great! You can participate to the party.")