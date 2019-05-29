<p align="center"><img src="https://www.seas.org.uk/wp-content/uploads/2014/05/Bees-and-Honey-banner.jpg" /></p>


# Cowrie Beautifier
Cowrie beautifier is a tool to convert Cowrie honeypot logs into JSON files:
* Login username and passwords sorted by most popular - { "user:pass": count }
* login username sorted by most popular  - { "username": count }
* login password sorted by most popular  - { "password": count }
* Shell commands sorted by most popular  - { "command": count }
* Wordlist employed by ip address - { "ip": { "user:pass": count_of_ssh_connections } } 


# Credits
* Special thanks for the creators of [cowrie honeypot](https://github.com/cowrie/cowrie).
