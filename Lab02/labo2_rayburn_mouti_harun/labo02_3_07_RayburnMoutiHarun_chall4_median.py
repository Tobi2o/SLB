address_list = []
with open("aslr-analyse.txt") as f:
    for line in f:
        address_list.append(int(line.strip(), 16))

# Sort the list of addresses
address_list.sort()

# Calculate the median
n = len(address_list)
if n == 0:
    print("The file is empty.")
elif n % 2 == 1:
    # Odd number of elements: middle one is the median
    median = address_list[n // 2]
else:
    # Even number of elements: average of the two middle elements
    median = (address_list[n // 2 - 1] + address_list[n // 2]) // 2

print(hex(median))
