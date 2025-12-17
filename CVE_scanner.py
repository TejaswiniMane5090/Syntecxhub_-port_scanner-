import socket

print("Simple Vulnerability Scanner")
print("-----------------------------")

target = input("Enter website or IP (example: google.com): ")

ports = [21, 22, 80, 443]

file = open("report.txt", "w")
file.write("Scan Report for " + target + "\n\n")

for port in ports:
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        print("Port", port, "OPEN")
        file.write("Port " + str(port) + " OPEN\n")
        s.close()
    except:
        print("Port", port, "CLOSED")
        file.write("Port " + str(port) + " CLOSED\n")

file.close()
print("\nScan finished. Report saved in report.txt")
